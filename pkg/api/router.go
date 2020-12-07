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

import "github.com/gorilla/mux"

type (
	// Router is an api router
	Router struct {
		*mux.Router
		s          *Server
		basePath   string
		version    string
		versioning bool
		name       string
	}

	// RouterOption specifies a router option
	RouterOption func(r *Router)
)

// AddRoutes adds a routes to the router
func (r *Router) AddRoutes(routes ...*Route) {
	for _, rt := range routes {
		r.Methods(rt.methods...).Path(rt.path).HandlerFunc(r.s.routeHandler(rt))
	}
}

// WithVersioning enables versioning that will enforce a versioned path
func WithVersioning(version string) RouterOption {
	return func(r *Router) {
		r.versioning = true
		r.version = version
	}
}

// WithName enables versioning that will enforce a versioned path
func WithName(name string) RouterOption {
	return func(r *Router) {
		r.name = name
	}
}

// Version implements the Versioner interface
func (r *Router) Version() string {
	return r.version
}

// Name implements the Versioner interface
func (r *Router) Name() string {
	return r.name
}
