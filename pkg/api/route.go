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

package api

import (
	"context"
	"net/http"
)

type (
	// Route defines an api route
	Route struct {
		methods     []string
		path        string
		handler     interface{}
		authorizers []Authorizer
		caching     bool
		validation  bool
		context     interface{}
		contextFunc ContextFunc
		router      *Router
	}

	// RouteOption defines route options
	RouteOption func(*Route)
)

// NewRoute returns a new route
func NewRoute(path string, opts ...RouteOption) Route {
	r := Route{
		path:    path,
		methods: make([]string, 0),
		handler: func(context.Context) {},
	}

	for _, opt := range opts {
		opt(&r)
	}

	return r
}

// WithMethods sets the methods for the route option
func WithMethods(m ...string) RouteOption {
	return func(r *Route) {
		r.methods = m
	}
}

// WithValidation sets the parameter validation which will be performed before the handler is called
func WithValidation() RouteOption {
	return func(o *Route) {
		o.validation = true
	}
}

// WithAuthorizers sets the authorizers
func WithAuthorizers(a ...Authorizer) RouteOption {
	return func(r *Route) {
		r.authorizers = a
	}
}

// WithHandler adds the handler to the route
func WithHandler(h interface{}) RouteOption {
	return func(r *Route) {
		r.handler = h
	}
}

// WithContextFunc adds a function that will allow the server to set additional context on every call
func WithContextFunc(c ContextFunc) RouteOption {
	return func(r *Route) {
		r.contextFunc = c
	}
}

// WithContext sets context for the route
func WithContext(c interface{}) RouteOption {
	return func(r *Route) {
		r.context = c
	}
}

// WithCaching enables content caching for the route
func WithCaching() RouteOption {
	return func(r *Route) {
		r.caching = true
	}
}

// Post adds post to the route
func (r Route) Post() Route {
	r.methods = append(r.methods, http.MethodPost)
	return r
}

// Put adds put to the route
func (r Route) Put() Route {
	r.methods = append(r.methods, http.MethodPut)
	return r
}

// Patch adds patch to the route
func (r Route) Patch() Route {
	r.methods = append(r.methods, http.MethodPatch)
	return r
}

// Get adds get to the route
func (r Route) Get() Route {
	r.methods = append(r.methods, http.MethodGet)
	return r
}

// Delete adds delete to the route
func (r Route) Delete() Route {
	r.methods = append(r.methods, http.MethodDelete)
	return r
}

// Handler sets the handler for the route
func (r Route) Handler(h interface{}) Route {
	r.handler = h
	return r
}

// Context sets the route context
func (r Route) Context(c interface{}) Route {
	r.context = c
	return r
}

// Authorizers sets the authorizers
func (r Route) Authorizers(a ...Authorizer) Route {
	r.authorizers = a
	return r
}

// Validate will validate parameters in the server
func (r Route) Validate() Route {
	r.validation = true
	return r
}
