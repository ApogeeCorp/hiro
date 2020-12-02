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
	"fmt"
	"net/http"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
)

type key int

const verKey key = 0

func (s *Server) versionMiddleware() func(http.Handler) http.Handler {
	apiVer, _ := semver.ParseTolerant(s.version)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vars := mux.Vars(r)

			ver, ok := vars["version"]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			pathVer, err := semver.ParseTolerant(ver)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			if pathVer.GT(apiVer) {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			r.URL.Path = strings.Replace(r.URL.Path, ver, pathVer.String(), 1)

			context.Set(r, verKey, ver)

			w.Header().Set("Server", fmt.Sprintf("%s/%s", s.name, s.serverVersion))

			next.ServeHTTP(w, r)
		})
	}
}

// RequestVersion returns the request version or the server version if not found
func (s *Server) RequestVersion(r *http.Request) string {
	ver := s.version

	if val, ok := context.GetOk(r, verKey); ok {
		ver = val.(string)
	}

	return ver
}
