package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	oidcrp "github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/app"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/otakakot/sample-oidc-rp-platform/pkg/rp"
)

func main() {
	prov, err := RP(context.Background())
	if err != nil {
		panic(err)
	}

	hdl, err := rp.NewServer(&Handler{
		provider: prov,
		uris:     make(map[string]url.URL),
		claims:   make(map[string]oidc.IDTokenClaims),
		tokens:   make(map[string]Token),
	})
	if err != nil {
		panic(err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           hdl,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	defer stop()

	go func() {
		slog.Info("start server listen")

		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	<-ctx.Done()

	slog.Info("start server shutdown")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		panic(err)
	}

	slog.Info("done server shutdown")
}

type Token struct {
	AccessToken  string
	RefreshToken string
}

var _ rp.Handler = (*Handler)(nil)

type Handler struct {
	uris     map[string]url.URL
	provider oidcrp.RelyingParty
	claims   map[string]oidc.IDTokenClaims
	tokens   map[string]Token
}

// Begin implements rp.Handler.
func (hdl *Handler) Begin(ctx context.Context, params rp.BeginParams) (rp.BeginRes, error) {
	slog.Info("rp begin")

	hdl.uris[params.State] = params.CallbackURI

	endpoint := oidcrp.AuthURL(params.State, hdl.provider)

	buf := new(bytes.Buffer)

	buf.WriteString(endpoint)

	location, _ := url.Parse(buf.String())

	cookie := http.Cookie{
		Name:  "state",
		Value: params.State,
	}

	return &rp.BeginFound{
		Location:  rp.NewOptURI(*location),
		SetCookie: rp.NewOptString(cookie.String()),
	}, nil
}

// Callback implements rp.Handler.
func (hdl *Handler) Callback(ctx context.Context, params rp.CallbackParams) (rp.CallbackRes, error) {
	slog.Info("rp callback")

	if params.CookieState != params.QueryState {
		return &rp.CallbackInternalServerError{}, nil
	}

	token, err := oidcrp.CodeExchange[*oidc.IDTokenClaims](ctx, params.Code, hdl.provider)
	if err != nil {
		return &rp.CallbackInternalServerError{}, err
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return &rp.CallbackInternalServerError{}, errors.New("id_token not found")
	}

	claims, err := oidcrp.VerifyIDToken[*oidc.IDTokenClaims](ctx, idToken, hdl.provider.IDTokenVerifier())
	if err != nil {
		return &rp.CallbackInternalServerError{}, err
	}

	hdl.claims[params.QueryState] = *claims

	hdl.tokens[params.QueryState] = Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	buf := new(bytes.Buffer)

	uri := hdl.uris[params.QueryState]

	buf.WriteString(uri.String())

	values := url.Values{
		"state": {params.QueryState},
	}

	buf.WriteString("?")

	buf.WriteString(values.Encode())

	location, _ := url.Parse(buf.String())

	return &rp.CallbackFound{
		Location: rp.NewOptURI(*location),
	}, nil
}

// End implements rp.Handler.
func (hdl *Handler) End(ctx context.Context, req *rp.EndReq) (rp.EndRes, error) {
	slog.Info("rp end")

	claim, ok := hdl.claims[req.State]
	if !ok {
		return &rp.EndInternalServerError{}, nil
	}

	token, ok := hdl.tokens[req.State]
	if !ok {
		return &rp.EndInternalServerError{}, nil
	}

	slog.Info(fmt.Sprintf("issuer: %s", claim.Issuer))
	slog.Info(fmt.Sprintf("subject: %s", claim.Subject))

	return &rp.EndOK{
		AcceesToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}, nil
}

func RP(
	ctx context.Context,
) (oidcrp.RelyingParty, error) {
	token := client.DefaultServiceUserAuthentication("../../machinekey/zitadel-admin-sa.json", oidc.ScopeOpenID, client.ScopeZitadelAPI())

	cli, err := client.New(
		ctx,
		zitadel.New("localhost", zitadel.WithInsecure("8080")),
		client.WithAuth(token),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	projects, err := cli.ManagementService().ListProjects(ctx, &management.ListProjectsRequest{})
	if err != nil {
		panic(err)
	}

	projectID := projects.Result[0].Id

	redirectURI := "http://localhost:4000/callback"

	app, err := cli.ManagementService().AddOIDCApp(ctx, &management.AddOIDCAppRequest{
		ProjectId:                projectID,
		Name:                     uuid.NewString(),
		RedirectUris:             []string{redirectURI},
		ResponseTypes:            []app.OIDCResponseType{app.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
		GrantTypes:               []app.OIDCGrantType{app.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE},
		AppType:                  app.OIDCAppType_OIDC_APP_TYPE_WEB,
		AuthMethodType:           app.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC,
		PostLogoutRedirectUris:   []string{},
		Version:                  0,
		DevMode:                  true,
		AccessTokenType:          app.OIDCTokenType_OIDC_TOKEN_TYPE_JWT,
		AccessTokenRoleAssertion: false,
		IdTokenRoleAssertion:     false,
		IdTokenUserinfoAssertion: false,
		ClockSkew:                &durationpb.Duration{},
		AdditionalOrigins:        []string{},
		SkipNativeAppSuccessPage: false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create app: %w", err)
	}

	email := fmt.Sprintf("%s@example.com", uuid.NewString())

	user, err := cli.ManagementService().AddHumanUser(ctx, &management.AddHumanUserRequest{
		UserName: uuid.NewString(),
		Profile: &management.AddHumanUserRequest_Profile{
			FirstName:   "test",
			LastName:    "test",
			NickName:    "test",
			DisplayName: "test",
		},
		Email: &management.AddHumanUserRequest_Email{
			Email:           email,
			IsEmailVerified: true,
		},
		InitialPassword: "Password1!",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	slog.Info(fmt.Sprintf("email: %s", email))

	if _, err := cli.ManagementService().SetHumanPassword(ctx, &management.SetHumanPasswordRequest{
		UserId:           user.UserId,
		Password:         "P@ssword1",
		NoChangeRequired: true,
	}); err != nil {
		return nil, fmt.Errorf("failed to set password: %w", err)
	}

	slog.Info("password: P@ssword1")

	provider, err := oidcrp.NewRelyingPartyOIDC(
		ctx,
		"http://localhost:8080",
		app.ClientId,
		app.ClientSecret,
		redirectURI,
		[]string{"openid"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create relying party: %w", err)
	}

	return provider, nil
}
