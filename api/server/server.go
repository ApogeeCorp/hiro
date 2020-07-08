//
//  TERALYTIC CONFIDENTIAL
//  _________________
//   2020 TERALYTIC
//   All Rights Reserved.
//
//   NOTICE:  All information contained herein is, and remains
//   the property of TERALYTIC and its suppliers,
//   if any.  The intellectual and technical concepts contained
//   herein are proprietary to TERALYTIC
//   and its suppliers and may be covered by U.S. and Foreign Patents,
//   patents in process, and are protected by trade secret or copyright law.
//   Dissemination of this information or reproduction of this material
//   is strictly forbidden unless prior written permission is obtained
//   from TERALYTIC.
//

// Package server provides an http api server
package server

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/Teralytic/oauth/pkg/oauth"
	"github.com/Teralytic/teralytic/pkg/teralytic"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type (
	// Server is an API server
	Server struct {
		// backend is the teralytic.Backend interface the server uses to complete requests
		backend   teralytic.Backend
		auth      oauth.Authorizer
		log       *logrus.Logger
		router    *mux.Router
		apiRouter *mux.Router
		addr      string
		srv       *http.Server
		lock      sync.Mutex
	}

	// Option provides the server options, these will override th defaults and any default
	// instance values.
	Option func(*Server)
)

var (
	// Permissions is the server api permissions from the spec doc
	Permissions = make([]string, 0)
)

func init() {
	for _, def := range SpecDoc.Spec().SecurityDefinitions {
		if def.Type != "oauth2" {
			continue
		}

		for scope := range def.Scopes {
			Permissions = append(Permissions, scope)
		}
	}
}

// New returns a new Server instance
func New(backend teralytic.Backend, auth oauth.Authorizer, opts ...Option) *Server {
	const (
		defaultAddr = "127.0.0.1:9000"
	)

	s := &Server{
		backend: backend,
		auth:    auth,
		log:     logrus.StandardLogger(),
		router:  mux.NewRouter(),
		addr:    defaultAddr,
	}

	for _, opt := range opts {
		opt(s)
	}

	s.apiRouter = s.router.PathPrefix("/api/{version}").Subrouter()
	s.apiRouter.Use(versionMiddleware())

	return s
}

// WithLogger specifies a new logger
func WithLogger(logger *logrus.Logger) Option {
	return func(s *Server) {
		if logger != nil {
			s.log = logger
		}
	}
}

// WithRouter specifies the router to use
func WithRouter(router *mux.Router) Option {
	return func(s *Server) {
		if router != nil {
			s.router = router
		}
	}
}

// WithAddr sets the listen address for the server
func WithAddr(addr string) Option {
	return func(s *Server) {
		if addr != "" {
			s.addr = addr
		}
	}
}

// Serve starts the http server
func (s *Server) Serve() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.srv != nil {
		return errors.New("server already running")
	}

	s.srv = &http.Server{
		Addr:    s.addr,
		Handler: s.router,
	}

	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Fatalf("listen: %s\n", err)
		}
	}()

	s.log.Debugf("http server listening on: %s", s.addr)

	return nil
}

// Shutdown shuts down the http server with the context
func (s *Server) Shutdown(ctx context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.srv == nil {
		s.log.Fatal("server already shutdown")
	}

	err := s.srv.Shutdown(ctx)

	s.srv = nil

	return err
}

// Handler returns the server http handler
func (s *Server) Handler() http.Handler {
	return s.router
}

// Router returns the server router
func (s *Server) Router() *mux.Router {
	return s.router
}
