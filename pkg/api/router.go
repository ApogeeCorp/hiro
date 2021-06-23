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
 * General Public License for more detailr.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

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
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path"
	"reflect"
	"runtime/debug"
	"strings"

	"github.com/ModelRocket/hiro/pkg/api/session"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/mr-tron/base58"
)

type (
	// Router is an api Router
	Router struct {
		*Server
		Mux         *mux.Router
		basePath    string
		version     string
		versioning  bool
		name        string
		context     func(context.Context) interface{}
		authorizers []Authorizer
		hooks       []RouteHook
		sessions    *session.Manager
	}

	// RouteHook methods are called before the handler to allow for added context
	RouteHook func(r *http.Request, rt Route) error

	// RouterOption are router options
	RouterOption func(r *Router)
)

// AddRoutes adds a routes to the router
func (r *Router) AddRoutes(routes ...Route) *Router {
	for _, rt := range routes {
		fn := reflect.ValueOf(rt)

		if fn.Kind() != reflect.Func {
			panic(fmt.Errorf("route %s is not a function", rt.Name()))
		}

		r.Mux.Name(rt.Name()).
			Methods(rt.Methods()...).
			Path(rt.Path()).
			HandlerFunc(r.handler(rt))
	}

	return r
}

// WithVersioning enables versioning that will enforce a versioned path
func WithVersioning(version ...string) RouterOption {
	return func(r *Router) {
		if len(version) > 0 {
			r.version = version[0]
		}
		r.versioning = true
		r.basePath = path.Join(r.basePath, "{version}")
		r.Mux = r.router.PathPrefix(r.basePath).Subrouter()
	}
}

// WithName enables versioning that will enforce a versioned path
func (r *Router) WithName(name string) RouterOption {
	return func(r *Router) {
		r.name = name
	}
}

// WithSessionManager adds the session store to the router
func WithSessionManager(store *session.Manager) RouterOption {
	return func(r *Router) {
		r.sessions = store
	}
}

// WithContext adds context to the router
func WithContext(ctx func(context.Context) interface{}) RouterOption {
	return func(r *Router) {
		r.context = ctx
	}
}

// WithHooks sets the hooks for the router
func WithHooks(hooks ...RouteHook) RouterOption {
	return func(r *Router) {
		r.hooks = hooks
	}
}

// WithAuthorizers sets the authorizers for the router
func WithAuthorizers(auth ...Authorizer) RouterOption {
	return func(r *Router) {
		r.authorizers = auth
	}
}

// Version implements the Versioner interface
func (r Router) Version() string {
	return r.version
}

// Name implements the Versioner interface
func (r Router) Name() string {
	return r.name
}

// RequireVersion implements the Versioner interface
func (r Router) RequireVersion() bool {
	return r.versioning
}

func (r *Router) handler(rt Route) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var resp interface{}
		var cache bool

		// add the log to the context
		id := uuid.Must(uuid.NewUUID())
		reqID := base58.Encode(id[:])

		log := r.log.
			WithField("req-id", reqID).
			WithField("route", rt.Name())

		*req = *req.WithContext(
			context.WithValue(
				req.Context(),
				contextKeyLogger,
				log))

		trace := r.tracingEnabled

		// disable caching if the header says so or its disabled via 0 ttl
		if req.Header.Get("Cache-Control") == "no-cache" || r.cache == nil {
			cache = false
		}

		// add the request object to the context
		rc := &requestContext{req, w}

		req = req.WithContext(context.WithValue(req.Context(), contextKeyRequest, rc))

		defer func() {
			if err := recover(); err != nil {
				if _, ok := err.(Responder); !ok {
					debug.PrintStack()

					if e, ok := err.(error); ok {
						r.WriteError(w, http.StatusInternalServerError, e)
					} else {
						w.WriteHeader(http.StatusInternalServerError)
					}

					return
				}

				// ensure the error is returned properly
				resp = err
			}

			switch t := resp.(type) {
			case Responder:
				if cache || trace {
					rec := httptest.NewRecorder()

					if err := t.Write(rec); err != nil {
						log.Error(err.Error())
						r.WriteError(w, http.StatusInternalServerError, err)
						return
					}

					dump, err := httputil.DumpResponse(rec.Result(), cache || rec.Body.Len() < 1024)
					if err != nil {
						log.Error(err.Error())
						r.WriteError(w, http.StatusInternalServerError, err)
						return
					}

					if trace {
						log.Debugf("%s <- %s", req.RequestURI, (dump))
					}

					if cr, ok := rt.(CachedRoute); ok && cache {
						r.cache.Set(req.RequestURI, dump, cr.Timeout())
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
					panic(err)
				}

			case *http.Response:
				t.Header.Write(w)
				t.Write(w)

			case error:
				r.WriteError(w, http.StatusInternalServerError, t)
			}
		}()

		if r.context != nil {
			req = req.WithContext(context.WithValue(req.Context(), contextKeyContext, r.context(req.Context())))
		}

		if r.sessions != nil {
			req = req.WithContext(context.WithValue(req.Context(), contextKeySessions, r.sessions))
		}

		if at, ok := rt.(AuthorizedRoute); ok {
			prins := make([]Principal, 0)

			for _, a := range r.authorizers {

				for _, ct := range at.RequireAuth() {
					if ct != a.CredentialType() {
						continue
					}

					ctx, err := a.Authorize(req, rt)
					if err != nil && !errors.Is(err, ErrAuthUnacceptable) {
						if re, ok := err.(Responder); ok {
							resp = re
						} else {
							panic(err)
						}
						return
					}

					if ctx != nil {
						// append this to the principal chain
						prins = append(prins, ctx)
					}
					break
				}
			}

			if len(prins) == 0 {
				panic(ErrUnauthorized)
			}

			req = req.WithContext(context.WithValue(req.Context(), contextKeyAuth, prins))
		}

		if _, ok := rt.(CachedRoute); ok && cache {
			if val, ok := r.cache.Get(req.RequestURI); ok {
				var err error

				resp, err = http.ReadResponse(bufio.NewReader(bytes.NewReader(val.([]byte))), req)
				if err != nil {
					resp = nil
					panic(err)
				}
			}
		}

		w.Header().Set("X-Hiro-Request-ID", reqID)

		rc.r = req

		// Add any additional context from the caller
		for _, h := range r.hooks {
			if err := h(req, rt); err != nil {
				panic(err)
			}
		}

		req = req.WithContext(context.WithValue(req.Context(), contextKeyRequest, rc))
		rc.r = req

		fn := reflect.ValueOf(rt)

		// check for standard HandlerFunc or http.HandlerFunc handlers
		if h, ok := fn.Interface().(HandlerFunc); ok {
			resp = h(w, req)
			return
		} else if h, ok := fn.Interface().(http.HandlerFunc); ok {
			h(w, req)
			return
		}

		args := []reflect.Value{}

		if fn.Type().In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
			panic(fmt.Errorf("first argument of handler must be context.Context"))
		}
		args = append(args, reflect.ValueOf(req.Context()))

		if fn.Type().NumIn() > 1 {
			pt := fn.Type().In(1)
			if pt.Kind() != reflect.Ptr {
				panic(ErrServerError.
					WithDetail(
						fmt.Sprintf("route %s %s parameter %s but be a pointer", req.Method, rt.Path(), pt.Name())))
			}

			pt = pt.Elem()

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

			vars := mux.Vars(req)
			if len(vars) > 0 {
				vals := make(url.Values)
				for k, v := range vars {
					vals.Add(k, v)
				}
				if err := decoder.Decode(params, vals); err != nil {
					panic(err)
				}
			}

			if len(req.URL.Query()) > 0 {
				if err := decoder.Decode(params, req.URL.Query()); err != nil {
					panic(err)
				}
			}

			if req.Body != nil && req.ContentLength > 0 {
				t, _, err := mime.ParseMediaType(req.Header.Get("Content-type"))
				if err != nil {
					panic(err)
				}

				switch t {
				case "application/json":
					data, err := ioutil.ReadAll(req.Body)
					if err != nil {
						panic(err)
					}

					if err := json.Unmarshal(data, params); err != nil {
						panic(err)
					}

					req.Body = ioutil.NopCloser(bytes.NewReader(data))

				case "application/x-www-form-urlencoded":
					if err := req.ParseForm(); err != nil {
						panic(err)
					}

					if err := decoder.Decode(params, req.Form); err != nil {
						panic(err)
					}

				case "multipart/form-data":
					if err := req.ParseMultipartForm(1024 * 1024 * 128); err != nil {
						panic(err)
					}

					if err := decoder.Decode(params, req.Form); err != nil {
						panic(err)
					}
				}
			}

			if v, ok := params.(validation.Validatable); ok {
				if err := v.Validate(); err != nil {
					panic(ErrBadRequest.WithError(err))
				}
			} else if v, ok := params.(validation.ValidatableWithContext); ok {
				if err := v.ValidateWithContext(req.Context()); err != nil {
					panic(ErrBadRequest.WithError(err))
				}
			}

			args = append(args, reflect.ValueOf(params))
		}

		if r.tracingEnabled {
			if dump, err := httputil.DumpRequest(req, true); err == nil {
				log.Debugf("%s -> %s", req.RequestURI, (dump))
			}
		}

		rc.r = req

		rval := fn.Call(args)
		if len(rval) > 0 {
			resp = rval[0].Interface()
		}
	}
}

// ServeHTTP implements the http.Handler interface
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.Mux.ServeHTTP(w, req)
}
