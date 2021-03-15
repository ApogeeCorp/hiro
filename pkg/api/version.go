/*************************************************************************
 * MIT License
 * Copyright (c) 2021 Model Rocket
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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

type (
	// Versioner provides a version
	Versioner interface {
		Name() string
		Version() string
		RequireVersion() bool
	}
)

var (
	contextKeyVersion = contextKey("api:version")
)

// VersionMiddleware enforces versioning in the request path
func VersionMiddleware(v Versioner, header ...string) func(http.Handler) http.Handler {
	apiVer, _ := semver.ParseTolerant(v.Version())

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vars := mux.Vars(r)

			if v.RequireVersion() {
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

				context.Set(r, contextKeyVersion, ver)
			}

			hdr := "Server"

			if len(header) > 0 {
				hdr = header[0]
			}

			w.Header().Set(hdr, fmt.Sprintf("%s/%s", v.Name(), v.Version()))

			next.ServeHTTP(w, r)
		})
	}
}

// RequestVersion returns the request version in the context
func RequestVersion(r *http.Request) string {
	var ver string

	if val, ok := context.GetOk(r, contextKeyVersion); ok {
		ver = val.(string)
	}

	return ver
}
