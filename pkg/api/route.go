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
		params      interface{}
		authorizers []Authorizer
		caching     bool
		validation  bool
		contextFunc func(context.Context) context.Context
	}

	// RouteOption defines route options
	RouteOption func(*Route)
)

// NewRoute returns a new route
func NewRoute(path string, handler interface{}, opts ...RouteOption) *Route {
	r := &Route{
		methods: []string{http.MethodGet},
		handler: handler,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// WithMethods sets the methods for the route option
func WithMethods(m ...string) RouteOption {
	return func(r *Route) {
		r.methods = m
	}
}

// WithParams sets the params for the route option
func WithParams(p interface{}) RouteOption {
	return func(r *Route) {
		r.params = p
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

// WithContext adds a function that will allow the server to set additional context on every call
func WithContext(c func(context.Context) context.Context) RouteOption {
	return func(r *Route) {
		r.contextFunc = c
	}
}

// WithCaching enables content caching for the route
func WithCaching() RouteOption {
	return func(r *Route) {
		r.caching = true
	}
}
