// Code generated by ogen, DO NOT EDIT.

package sp

import (
	"context"
)

// Handler handles operations described by OpenAPI v3 specification.
type Handler interface {
	// Auth implements auth operation.
	//
	// Auth.
	//
	// GET /auth
	Auth(ctx context.Context) (AuthRes, error)
	// Callback implements callback operation.
	//
	// Callback.
	//
	// GET /callback
	Callback(ctx context.Context, params CallbackParams) (CallbackRes, error)
	// Index implements index operation.
	//
	// Index.
	//
	// GET /
	Index(ctx context.Context) (IndexRes, error)
}

// Server implements http server based on OpenAPI v3 specification and
// calls Handler to handle requests.
type Server struct {
	h Handler
	baseServer
}

// NewServer creates new Server.
func NewServer(h Handler, opts ...ServerOption) (*Server, error) {
	s, err := newServerConfig(opts...).baseServer()
	if err != nil {
		return nil, err
	}
	return &Server{
		h:          h,
		baseServer: s,
	}, nil
}
