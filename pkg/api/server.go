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
	"io/ioutil"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"reflect"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/allegro/bigcache"
	"github.com/apex/log"
	"github.com/apex/log/handlers/discard"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/spf13/cast"
)

type (
	// Authorizer performs an autorization and returns a context or error on failure
	Authorizer func(r *http.Request) (context.Context, error)

	// Server is an http server that provides basic REST funtionality
	Server struct {
		log           log.Interface
		router        *mux.Router
		apiRouter     *mux.Router
		addr          string
		listener      net.Listener
		srv           *http.Server
		lock          sync.Mutex
		basePath      string
		name          string
		version       string
		serverVersion string
		versioning    bool
		corsOrigin    []string
		cache         *bigcache.BigCache
		cacheTTL      time.Duration
	}

	routeOption struct {
		method      string
		params      interface{}
		validate    bool
		contextFunc ContextFunc
		authorizers []Authorizer
		cache       bool
	}

	// RouteOption defines route options
	RouteOption func(*routeOption)

	// Parameters interface handles binding requests
	Parameters interface {
		Validate() error
	}

	// ContextFunc adds context to a request
	ContextFunc func(context.Context) context.Context

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
	contextKeyLogger = contextKey("logger")

	contextKeyRequest = contextKey("request")

	contextKeyBody = contextKey("body")
)

// NewServer creates a new server object
func NewServer(opts ...Option) *Server {
	const (
		defaultAddr     = "127.0.0.1:9000"
		defaultBasePath = "/api/{version}"
		defaultName     = "Atomic"
		defaultVersion  = "1.0.0"
		defaultCacheTTL = time.Hour
	)

	s := &Server{
		log:        log.Log,
		router:     mux.NewRouter(),
		addr:       defaultAddr,
		name:       defaultName,
		version:    defaultVersion,
		versioning: false,
		basePath:   defaultBasePath,
		cacheTTL:   defaultCacheTTL,
	}

	for _, opt := range opts {
		opt(s)
	}

	s.apiRouter = s.router.PathPrefix(s.basePath).Subrouter()

	s.apiRouter.Use(s.LogMiddleware())

	if s.versioning {
		s.apiRouter.Use(s.versionMiddleware())
	}

	s.cache, _ = bigcache.NewBigCache(bigcache.DefaultConfig(s.cacheTTL))

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
				"X-Total-Count",
				"X-Atom-Link",
				"X-Last-Entry-Date",
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

// Handler returns the server http handler
func (s *Server) Handler() http.Handler {
	return s.router
}

// Router returns the server router
func (s *Server) Router() *mux.Router {
	return s.router
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// AddRoute adds a route in the clear
func (s *Server) AddRoute(path string, handler interface{}, opts ...RouteOption) {
	opt := &routeOption{
		method: http.MethodGet,
	}

	for _, o := range opts {
		o(opt)
	}

	s.apiRouter.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		var resp interface{}

		cache := opt.cache
		trace := cast.ToBool(os.Getenv("HTTP_TRACE_ENABLE"))

		if r.Header.Get("Cache-Control") == "no-cache" {
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

		if len(opt.authorizers) > 0 && opt.authorizers[0] != nil {
			for _, a := range opt.authorizers {
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

				// add the auth context to the context
				if ctx != nil {
					r = r.WithContext(ctx)
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
		r = r.WithContext(context.WithValue(r.Context(), contextKeyLogger, s.log))
		rc.r = r

		// Add any additional context from the caller
		if opt.contextFunc != nil {
			r = r.WithContext(opt.contextFunc(r.Context()))
		}

		r = r.WithContext(context.WithValue(r.Context(), contextKeyRequest, rc))
		rc.r = r

		if h, ok := handler.(func(http.ResponseWriter, *http.Request) Responder); ok {
			resp = h(w, r)
			return
		} else if h, ok := handler.(func(http.ResponseWriter, *http.Request)); ok {
			h(w, r)
			return
		}

		var pv reflect.Value

		if opt.params != nil {
			pt := reflect.TypeOf(opt.params)
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
					r = r.WithContext(context.WithValue(r.Context(), contextKeyBody, data))

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

			if opt.validate {
				if v, ok := params.(Parameters); ok {
					if err := v.Validate(); err != nil {
						s.log.Error(err.Error())
						s.WriteError(w, http.StatusBadRequest, err)
						return
					}
				}
			}

			pv = reflect.ValueOf(params)
		} else {
			pv = reflect.Zero(reflect.TypeOf((*interface{})(nil)).Elem())
		}

		fn := reflect.ValueOf(handler)
		args := []reflect.Value{}

		// support optional context as first parameter
		narg := 0
		if fn.Type().In(0) == reflect.TypeOf((*context.Context)(nil)).Elem() {
			args = append(args, reflect.ValueOf(r.Context()))
			narg++
		}
		if fn.Type().NumIn() > narg {
			args = append(args, pv)
		}

		if _, ok := os.LookupEnv("HTTP_TRACE_ENABLE"); ok {
			if dump, err := httputil.DumpRequest(r, true); err == nil {
				s.log.Debugf("%s -> %s", r.RequestURI, (dump))
			}
		}

		rc.r = r

		rval := fn.Call(args)
		if len(rval) > 0 {
			resp = rval[0].Interface()
		}

	}).Methods(opt.method)
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

// WithRouter specifies the router to use
func WithRouter(router *mux.Router) Option {
	return func(s *Server) {
		if router != nil {
			s.router = router
			s.apiRouter = s.router.PathPrefix(s.basePath).Subrouter()

			if s.versioning {
				s.apiRouter.Use(s.versionMiddleware())
			}
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

// WithBasepath sets the router basepath for the api
func WithBasepath(base string) Option {
	return func(s *Server) {
		s.basePath = base
	}
}

// WithVersioning enables versioning that will enforce a versioned path
// and optionally set the Server header to the serverVersion
func WithVersioning(version string, serverVersion ...string) Option {
	return func(s *Server) {
		s.versioning = true
		s.version = version

		if len(serverVersion) > 0 {
			s.serverVersion = serverVersion[0]
		} else {
			s.serverVersion = version
		}
	}
}

// WithName specifies the server name
func WithName(name string) Option {
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

// WithMethod sets the method for the route option
func WithMethod(m string) RouteOption {
	return func(r *routeOption) {
		r.method = m
	}
}

// WithParams sets the params for the route option
func WithParams(p interface{}) RouteOption {
	return func(r *routeOption) {
		r.params = p
	}
}

// WithContextFunc sets the context handler for the route option
func WithContextFunc(f ContextFunc) RouteOption {
	return func(r *routeOption) {
		r.contextFunc = f
	}
}

// WithValidation sets the parameter validation
func WithValidation(v bool) RouteOption {
	return func(o *routeOption) {
		o.validate = true
	}
}

// WithAuthorizers sets the authorizers
func WithAuthorizers(a ...Authorizer) RouteOption {
	return func(r *routeOption) {
		r.authorizers = a
	}
}

// WithCaching enables content caching for the route
func WithCaching() RouteOption {
	return func(r *routeOption) {
		r.cache = true
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

// Request gets the reqest and response objects from the context
func Request(ctx context.Context) (*http.Request, http.ResponseWriter) {
	l := ctx.Value(contextKeyRequest)
	if r, ok := l.(*requestContext); ok {
		return r.r, r.w
	}
	return nil, nil
}

// RequestBody returns the raw request body
func RequestBody(ctx context.Context) []byte {
	return ctx.Value(contextKeyBody).([]byte)
}

// Log returns the server log
func (s *Server) Log() log.Interface {
	return s.log
}
