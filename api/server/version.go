/*
 * Copyright (C) 2020 Model Rocket
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */
package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/gorilla/mux"
)

const (
	// Name the server name
	Name = "Hiro"

	// Version is the binary version
	Version = "1.0.0"
)

var (
	apiVer semver.Version
)

func init() {
	apiVer, _ = semver.Make(Version)
}

func versionMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vars := mux.Vars(r)
			v := strings.TrimPrefix("", "/")

			ver, ok := vars["version"]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			if ver != v {
				pathVer, err := semver.ParseTolerant(ver)
				if err != nil {
					w.WriteHeader(http.StatusNotFound)
					return
				}

				if pathVer.GT(apiVer) {
					w.WriteHeader(http.StatusNotFound)
					return
				}

				r.URL.Path = strings.Replace(r.URL.Path, ver, v, 1)
			}

			w.Header().Set("Server", fmt.Sprintf("%s/%s", Name, Version))

			next.ServeHTTP(w, r)
		})
	}
}
