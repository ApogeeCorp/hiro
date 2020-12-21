/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://github.com/ModelRocket/hiro
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

// Package api is the hiro api helper library
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ModelRocket/hiro/pkg/api/session"
	"github.com/apex/log"
	"github.com/apex/log/handlers/discard"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/patrickmn/go-cache"
)

type (
	// Server is an http server that provides basic REST funtionality
	Server struct {
		log            log.Interface
		router         *mux.Router
		addr           string
		listener       net.Listener
		srv            *http.Server
		lock           sync.Mutex
		basePath       string
		name           string
		version        string
		corsOrigin     []string
		cache          *cache.Cache
		cacheTTL       time.Duration
		tracingEnabled bool
	}

	// HandlerFunc is a generic handler server operations
	HandlerFunc func(http.ResponseWriter, *http.Request) Responder

	// Option provides the server options, these will override th defaults and any hiro
	// instance values.
	Option func(*Server)

	contextKey string

	requestContext struct {
		r *http.Request
		w http.ResponseWriter
	}
)

var (
	contextKeyLogger = contextKey("api:logger")

	contextKeyRequest = contextKey("api:request")

	contextKeyContext = contextKey("api:context")

	contextKeySessions = contextKey("api:sessions")
)

// NewServer creates a new server object
func NewServer(opts ...Option) *Server {
	const (
		defaultAddr     = "127.0.0.1:9000"
		defaultCacheTTL = time.Hour
		defaultVersion  = "1.0.0"
		defaultName     = "hiro"
	)

	s := &Server{
		log:      log.Log,
		router:   mux.NewRouter(),
		addr:     defaultAddr,
		cacheTTL: defaultCacheTTL,
		version:  defaultVersion,
		name:     defaultName,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.basePath != "" {
		s.router = s.router.PathPrefix(s.basePath).Subrouter()
	}

	s.router.Use(s.LogMiddleware())
	s.router.Use(VersionMiddleware(s))

	if len(s.corsOrigin) > 0 {
		s.router.Use(handlers.CORS(
			handlers.AllowedOrigins(s.corsOrigin),
			handlers.AllowedMethods([]string{"OPTIONS", "HEAD", "GET", "POST", "PUT", "DELETE"}),
			handlers.ExposedHeaders([]string{
				"X-API-Version",
				"Server",
				"Content-Length",
				"Content-Range",
			}),
			handlers.AllowedHeaders([]string{
				"Accept",
				"Accept-Language",
				"Authorization",
				"Content-Type",
				"Content-Language",
				"Origin",
				"Range",
				"If-Modified-Since",
				"X-Forwarded-For",
				"X-Original-Method",
				"X-Redirected-From"}),
			handlers.AllowCredentials(),
		))
	}

	if s.cacheTTL > 0 {
		s.cache = cache.New(s.cacheTTL, s.cacheTTL*2)
	}

	return s
}

// Serve starts the http server
func (s *Server) Serve() error {
	var listener net.Listener
	var err error

	s.lock.Lock()
	defer s.lock.Unlock()

	if s.srv != nil {
		return errors.New("server already running")
	}

	s.srv = &http.Server{
		Handler: s.router,
	}

	if s.listener != nil {
		listener = s.listener
	} else if s.addr != "" {
		listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			return err
		}
	} else {
		return errors.New("server address not set")
	}

	go func() {
		if err := s.srv.Serve(listener); err != nil && err != http.ErrServerClosed {
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

// Router returns an api router at the specified base path
func (s *Server) Router(basePath string, opts ...RouterOption) *Router {
	const (
		defaultVersion = "1.0.0"
	)

	r := &Router{
		Server:     s,
		Mux:        s.router.PathPrefix(basePath).Subrouter(),
		basePath:   basePath,
		version:    defaultVersion,
		versioning: false,
		name:       s.name,
	}

	for _, opt := range opts {
		opt(r)
	}

	r.Mux.Use(VersionMiddleware(r, "X-API-Version"))

	return r
}

// ServeHTTP implements the http.Handler interface
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// WriteJSON writes out json
func (s *Server) WriteJSON(w http.ResponseWriter, status int, v interface{}, pretty ...bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	if len(pretty) > 0 && pretty[0] {
		enc.SetIndent("", "\t")
	}

	if err := enc.Encode(v); err != nil {
		s.log.Error(err.Error())
	}
}

// WriteError writes an error object
func (s *Server) WriteError(w http.ResponseWriter, status int, err error) {
	out := struct {
		Message string `json:"message"`
		Error   error  `json:"error,omitempty"`
	}{
		Message: err.Error(),
	}

	if e, ok := err.(validation.Error); ok {
		out.Error = e
	}

	s.WriteJSON(w, status, out)
}

// Version implements the Versioner interface
func (s *Server) Version() string {
	return s.version
}

// Name implements the Versioner interface
func (s *Server) Name() string {
	return s.name
}

// RequireVersion implements the Versioner interface
func (s *Server) RequireVersion() bool {
	return false
}

// WithLog specifies a new logger
func WithLog(l log.Interface) Option {
	return func(s *Server) {
		if l != nil {
			s.log = l
		}
	}
}

// WithCORS sets the cors origin and enables cors on the router
func WithCORS(origin ...string) Option {
	return func(s *Server) {
		s.corsOrigin = origin
	}
}

// WithTracing enables http tracing
func WithTracing(t bool) Option {
	return func(s *Server) {
		s.tracingEnabled = t
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

// WithListener sets the net listener for the server
func WithListener(l net.Listener) Option {
	return func(s *Server) {
		s.listener = l
	}
}

// WithVersion sets the specific version for the server
func WithVersion(v string) Option {
	return func(s *Server) {
		s.version = v
	}
}

// WithBasepath sets the router basepath for the api
func WithBasepath(base string) Option {
	return func(s *Server) {
		s.basePath = base
	}
}

// WithServerName specifies the server name
func WithServerName(name string) Option {
	return func(s *Server) {
		s.name = name
	}
}

// WithCache enables content caching for the route
func WithCache(ttl time.Duration) Option {
	return func(s *Server) {
		s.cacheTTL = ttl
	}
}

// Log returns the logger
func Log(ctx context.Context) log.Interface {
	l := ctx.Value(contextKeyLogger)
	if l != nil {
		return l.(log.Interface)
	}

	logger := &log.Logger{
		Handler: discard.Default,
	}

	return logger
}

// IsRequest returns true if the context is an http.Request
func IsRequest(ctx context.Context) bool {
	_, ok := ctx.Value(contextKeyRequest).(*requestContext)
	return ok
}

// Context returns the request context object
func Context(ctx context.Context) interface{} {
	return ctx.Value(contextKeyContext)
}

// SessionManager returns the session store from the context
func SessionManager(ctx context.Context) *session.Manager {
	return ctx.Value(contextKeySessions).(*session.Manager)
}

// Request gets the reqest and response objects from the context
func Request(ctx context.Context) (*http.Request, http.ResponseWriter) {
	l := ctx.Value(contextKeyRequest)
	if r, ok := l.(*requestContext); ok {
		return r.r, r.w
	}
	return nil, nil
}

// Version returns the request version from the context
func Version(ctx context.Context) string {
	l := ctx.Value(contextKeyRequest)
	if r, ok := l.(*requestContext); ok {
		return RequestVersion(r.r)
	}
	return ""
}

// Log returns the server log
func (s *Server) Log() log.Interface {
	return s.log
}
