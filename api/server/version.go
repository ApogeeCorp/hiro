//
//  TERALYTIC CONFIDENTIAL
//  _________________
//   2020 TERALYTIC
//   All Rights Reserved.
//
//   NOTICE:  All information contained herein is, and remains
//   the property of TERALYTIC and its suppliers,
//   if any.  The intellectual and technical concepts contained
//   herein are proprietary to TERALYTIC
//   and its suppliers and may be covered by U.S. and Foreign Patents,
//   patents in process, and are protected by trade secret or copyright law.
//   Dissemination of this information or reproduction of this material
//   is strictly forbidden unless prior written permission is obtained
//   from TERALYTIC.
//
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
	Name = "Teralytic"

	// Version is the binary version
	Version = "2.0.0"
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
