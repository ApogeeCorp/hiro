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
	"github.com/ModelRocket/hiro/pkg/api/session"
	"github.com/gorilla/mux"
)

type (
	// Router is a router interface
	Router interface {
		AddRoutes(routes ...Route)
	}

	// router is an api router
	router struct {
		*mux.Router
		s          *Server
		basePath   string
		version    string
		versioning bool
		name       string
		sessions   *session.Manager
	}

	// RouterOption specifies a router option
	RouterOption func(r *router)
)

// AddRoutes adds a routes to the router
func (r *router) AddRoutes(routes ...Route) {
	for _, rt := range routes {
		rt.router = r
		r.Methods(rt.methods...).Path(rt.path).HandlerFunc(r.s.routeHandler(rt))
	}
}

// WithVersioning enables versioning that will enforce a versioned path
func WithVersioning(version string) RouterOption {
	return func(r *router) {
		r.versioning = true
		r.version = version
	}
}

// WithName enables versioning that will enforce a versioned path
func WithName(name string) RouterOption {
	return func(r *router) {
		r.name = name
	}
}

// WithSessionStore adds the session store to the router
func WithSessionStore(store *session.Manager) RouterOption {
	return func(r *router) {
		r.sessions = store
	}
}

// Version implements the Versioner interface
func (r *router) Version() string {
	return r.version
}

// Name implements the Versioner interface
func (r *router) Name() string {
	return r.name
}
