package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/otakakot/sample-oidc-rp-platform/pkg/rp"
	"github.com/otakakot/sample-oidc-rp-platform/pkg/sp"
)

func main() {
	hdl, err := sp.NewServer(&Handler{})
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

var _ sp.Handler = (*Handler)(nil)

type Handler struct{}

const index = `
<!DOCTYPE html>
<html>
<head>
    <style>
        .center {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
    </style>
    <script>
        function navigate() {
            window.location.href = "http://localhost:3000/auth";
        }
    </script>
</head>
<body>
    <div class="center">
        <button type="button" onclick="navigate()">ログイン</button>
    </div>
</body>
</html>
`

// Index implements sp.Handler.
func (*Handler) Index(ctx context.Context) (sp.IndexRes, error) {
	tmp, _ := template.New("index").Parse(index)

	buf := new(bytes.Buffer)

	if err := tmp.Execute(buf, nil); err != nil {
		return &sp.IndexInternalServerError{}, nil
	}

	return &sp.IndexOK{
		Data: buf,
	}, nil
}

// Auth implements sp.Handler.
func (*Handler) Auth(ctx context.Context) (sp.AuthRes, error) {
	slog.Info("sp auth")

	buf := new(bytes.Buffer)

	buf.WriteString("http://localhost:4000/auth")

	state := uuid.New().String()

	values := url.Values{
		"state":        {state},
		"callback_uri": {"http://localhost:3000/callback"},
	}

	buf.WriteString("?")

	buf.WriteString(values.Encode())

	location, _ := url.Parse(buf.String())

	cookie := http.Cookie{
		Name:  "state",
		Value: state,
	}

	return &sp.AuthFound{
		Location:  sp.NewOptURI(*location),
		SetCookie: sp.NewOptString(cookie.String()),
	}, nil
}

// Callback implements sp.Handler.
func (*Handler) Callback(ctx context.Context, params sp.CallbackParams) (sp.CallbackRes, error) {
	slog.Info("sp callback")

	cli, err := rp.NewClient("http://localhost:4000")
	if err != nil {
		return nil, err
	}

	if params.CookieState != params.QueryState {
		return &sp.CallbackInternalServerError{}, nil
	}

	res, err := cli.End(ctx, &rp.EndReq{
		State: params.QueryState,
	})
	if err != nil {
		return nil, err
	}

	if _, ok := res.(*rp.EndInternalServerError); ok {
		return nil, errors.New("internal server error")
	}

	if _, ok := res.(*rp.EndOK); !ok {
		return nil, errors.New("unexpected response")
	}

	result := res.(*rp.EndOK)

	slog.Info(fmt.Sprintf("accees_token: %v", result.GetAcceesToken()))
	slog.Info(fmt.Sprintf("refresh_token: %v", result.GetRefreshToken()))

	cookie := http.Cookie{
		Name:   "state",
		Value:  "",
		MaxAge: -1,
	}

	jb, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return &sp.CallbackOKHeaders{
		SetCookie: sp.NewOptString(cookie.String()),
		Response: sp.CallbackOK{
			Data: bytes.NewReader(jb),
		},
	}, nil
}
