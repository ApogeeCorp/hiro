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
	"path"

	"github.com/ModelRocket/hiro/pkg/api/session"
	"github.com/gorilla/mux"
)

type (
	// Router is an api Router
	Router struct {
		*mux.Router
		s          *Server
		basePath   string
		version    string
		versioning bool
		name       string
		sessions   *session.Manager
	}
)

// WithRoutes adds a routes to the router
func (r *Router) WithRoutes(routes ...Route) *Router {
	for _, rt := range routes {
		rt.router = r
		r.Methods(rt.methods...).
			Path(rt.path).
			HandlerFunc(r.s.routeHandler(rt))
	}

	return r
}

// WithVersioning enables versioning that will enforce a versioned path
func (r *Router) WithVersioning() *Router {
	r.versioning = true
	r.basePath = path.Join(r.basePath, "{version}")
	r.Router = r.s.router.PathPrefix(r.basePath).Subrouter()
	return r
}

// WithName enables versioning that will enforce a versioned path
func (r *Router) WithName(name string) *Router {
	r.name = name
	return r
}

// WithSessionManager adds the session store to the router
func (r *Router) WithSessionManager(store *session.Manager) *Router {
	r.sessions = store
	return r
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
