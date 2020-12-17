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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/ModelRocket/hiro/pkg/api/session"
	"github.com/allegro/bigcache"
	"github.com/apex/log"
	"github.com/apex/log/handlers/discard"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/mr-tron/base58"
)

type (
	// Authorizer performs an authorization and returns a context or error on failure
	Authorizer func(r *http.Request) (interface{}, error)

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
		cache          *bigcache.BigCache
		cacheTTL       time.Duration
		tracingEnabled bool
	}

	// HandlerFunc is a generic handler server operations
	HandlerFunc func(http.ResponseWriter, *http.Request) Responder

	// ContextFunc adds context to a request
	ContextFunc func(context.Context) interface{}

	// Option provides the server options, these will override th defaults and any atomic
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

	contextKeyAuth = contextKey("api:auth")
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

	if s.cacheTTL > 0 {
		s.cache, _ = bigcache.NewBigCache(bigcache.DefaultConfig(s.cacheTTL))
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

	handler := http.Handler(s.router)

	if len(s.corsOrigin) > 0 {
		handler = handlers.CORS(
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
		)(handler)
	}

	s.srv = &http.Server{
		Handler: handler,
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
func (s *Server) Router(basePath string, version ...string) *Router {
	const (
		defaultVersion = "1.0.0"
	)

	r := &Router{
		Router:     s.router.PathPrefix(basePath).Subrouter(),
		basePath:   basePath,
		version:    defaultVersion,
		versioning: false,
		name:       s.name,
		s:          s,
	}

	if len(version) > 0 {
		r.version = version[0]
	}

	r.Use(VersionMiddleware(r, "X-API-Version"))

	return r
}

// ServeHTTP implements the http.Handler interface
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) routeHandler(route Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var resp interface{}

		cache := route.caching
		trace := s.tracingEnabled

		// disable caching if the header says so or its disabled via 0 ttl
		if r.Header.Get("Cache-Control") == "no-cache" || s.cache == nil {
			cache = false
		}

		// add the request object to the context
		rc := &requestContext{r, w}

		r = r.WithContext(context.WithValue(r.Context(), contextKeyRequest, rc))

		defer func() {
			if err := recover(); err != nil {
				debug.PrintStack()

				if e, ok := err.(error); ok {
					s.WriteError(w, http.StatusInternalServerError, e)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}

				return
			}

			switch t := resp.(type) {
			case Responder:
				if cache || trace {
					rec := httptest.NewRecorder()

					if err := t.Write(rec); err != nil {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusInternalServerError, err)
						return
					}

					dump, err := httputil.DumpResponse(rec.Result(), cache || rec.Body.Len() < 1024)
					if err != nil {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusInternalServerError, err)
						return
					}

					if trace {
						s.log.Debugf("%s <- %s", r.RequestURI, (dump))
					}

					if cache {
						s.cache.Set(r.RequestURI, dump)
					}

					for k, vals := range rec.Header() {
						for _, v := range vals {
							w.Header().Add(k, v)
						}
					}
					w.WriteHeader(rec.Code)
					w.Write(rec.Body.Bytes())

					return
				}

				if err := t.Write(w); err != nil {
					s.log.Error(err.Error())
					s.WriteError(w, http.StatusInternalServerError, err)
				}

			case *http.Response:
				t.Header.Write(w)
				t.Write(w)

			case error:
				s.WriteError(w, http.StatusInternalServerError, t)
			}
		}()

		if route.router.sessions != nil {
			r = r.WithContext(context.WithValue(r.Context(), contextKeySessions, route.router.sessions))
		}

		if len(route.authorizers) > 0 && route.authorizers[0] != nil {
			for _, a := range route.authorizers {
				ctx, err := a(r)
				if err != nil {
					if r, ok := err.(Responder); ok {
						resp = r
					} else {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusUnauthorized, err)
					}
					return
				}

				// add the first context we get and break
				if ctx != nil {
					r = r.WithContext(context.WithValue(r.Context(), contextKeyAuth, ctx))
					break
				}
			}
		}

		if cache {
			if val, err := s.cache.Get(r.RequestURI); err == nil {
				resp, err = http.ReadResponse(bufio.NewReader(bytes.NewReader(val)), r)
				if err != nil {
					resp = nil
					s.log.Error(err.Error())
					s.WriteError(w, http.StatusInternalServerError, err)
					return
				}
			}
		}

		// add the log to the context
		id := uuid.Must(uuid.NewUUID())
		reqID := base58.Encode(id[:])

		r = r.WithContext(
			context.WithValue(
				r.Context(),
				contextKeyLogger,
				s.log.WithField("req-id", reqID)))

		w.Header().Set("X-Hiro-Request-ID", reqID)

		rc.r = r

		// Add any additional context from the caller
		if route.contextFunc != nil {
			if c := route.contextFunc(r.Context()); c != nil {
				r = r.WithContext(context.WithValue(r.Context(), contextKeyContext, c))
			}
		} else if route.context != nil {
			r = r.WithContext(context.WithValue(r.Context(), contextKeyContext, route.context))
		}

		r = r.WithContext(context.WithValue(r.Context(), contextKeyRequest, rc))
		rc.r = r

		// check for standard HandlerFunc or http.HandlerFunc handlers
		if h, ok := route.handler.(HandlerFunc); ok {
			resp = h(w, r)
			return
		} else if h, ok := route.handler.(http.HandlerFunc); ok {
			h(w, r)
			return
		}

		fn := reflect.ValueOf(route.handler)
		args := []reflect.Value{}

		if fn.Type().In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
			panic(fmt.Errorf("first argument of handler must be context.Context"))
		}
		args = append(args, reflect.ValueOf(r.Context()))

		if fn.Type().NumIn() > 1 {
			pt := fn.Type().In(1)
			if pt.Kind() == reflect.Ptr {
				pt = pt.Elem()
			}
			params := reflect.New(pt).Interface()

			decoder := schema.NewDecoder()
			decoder.SetAliasTag("json")
			decoder.IgnoreUnknownKeys(true)

			decoder.RegisterConverter([]string{}, func(input string) reflect.Value {
				if strings.Contains(input, ",") {
					return reflect.ValueOf(strings.Split(input, ","))
				}
				return reflect.ValueOf(strings.Fields(input))
			})

			vars := mux.Vars(r)
			if len(vars) > 0 {
				vals := make(url.Values)
				for k, v := range vars {
					vals.Add(k, v)
				}
				if err := decoder.Decode(params, vals); err != nil {
					s.log.Error(err.Error())
					s.WriteError(w, http.StatusBadRequest, err)
					return
				}
			}

			if len(r.URL.Query()) > 0 {
				if err := decoder.Decode(params, r.URL.Query()); err != nil {
					s.log.Error(err.Error())
					s.WriteError(w, http.StatusBadRequest, err)
					return
				}
			}

			if r.Body != nil && r.ContentLength > 0 {
				t, _, err := mime.ParseMediaType(r.Header.Get("Content-type"))
				if err != nil {
					s.log.Error(err.Error())
					s.WriteError(w, http.StatusBadRequest, err)
					return
				}

				switch t {
				case "application/json":
					data, err := ioutil.ReadAll(r.Body)
					if err != nil {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusBadRequest, err)
						return
					}

					if err := json.Unmarshal(data, params); err != nil {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusBadRequest, err)
						return
					}

					r.Body = ioutil.NopCloser(bytes.NewReader(data))

				case "application/x-www-form-urlencoded":
					if err := r.ParseForm(); err != nil {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusBadRequest, err)
						return
					}

					if err := decoder.Decode(params, r.Form); err != nil {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusBadRequest, err)
						return
					}

				case "multipart/form-data":
					if err := r.ParseMultipartForm(1024 * 1024 * 128); err != nil {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusBadRequest, err)
						return
					}

					if err := decoder.Decode(params, r.Form); err != nil {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusBadRequest, err)
						return
					}
				}
			}

			if route.validation {
				if v, ok := params.(validation.Validatable); ok {
					if err := v.Validate(); err != nil {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusBadRequest, err)
						return
					}
				} else if v, ok := params.(validation.ValidatableWithContext); ok {
					if err := v.ValidateWithContext(r.Context()); err != nil {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusBadRequest, err)
						return
					}
				}
			}

			args = append(args, reflect.ValueOf(params))
		}

		if s.tracingEnabled {
			if dump, err := httputil.DumpRequest(r, true); err == nil {
				s.log.Debugf("%s -> %s", r.RequestURI, (dump))
			}
		}

		rc.r = r

		rval := fn.Call(args)
		if len(rval) > 0 {
			resp = rval[0].Interface()
		}
	}
}

// AddRoutes adds a routes to the router
func (s *Server) AddRoutes(routes ...Route) {
	for _, r := range routes {
		s.router.Methods(r.methods...).Path(r.path).HandlerFunc(s.routeHandler(r))
	}
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

// AuthContext returns the request auth context
func AuthContext(ctx context.Context) interface{} {
	return ctx.Value(contextKeyAuth)
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
