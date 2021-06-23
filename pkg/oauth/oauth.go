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

// Package oauth provides the base auth interfaces
package oauth

import (
	"context"
	"errors"
	"net/url"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/bmatcuk/doublestar"
)

var (
	// PasscodeLength is the length of random passcodes to generate for OTPs
	PasscodeLength = 6

	// SessionPrefix is the prefix used for session names
	SessionPrefix = "hiro-session#"
)

// EnsureURI checks that a uri matches within a list
func EnsureURI(ctx context.Context, uri string, search []string) (*url.URL, error) {
	if search == nil || len(search) == 0 {
		return nil, errors.New("unauthorized uri")
	}

	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	r, _ := api.Request(ctx)
	if r != nil && u.Host == r.Host {
		u.Host = ""
		u.Scheme = ""
	}

	for _, a := range search {
		if a == u.String() {
			return u, nil
		}

		uu, _ := url.Parse(a)

		if r != nil && uu.Host == r.Host {
			uu.Host = ""
			uu.Scheme = ""
		}

		if uu.Scheme == u.Scheme && u.Host == uu.Host {
			if ok, _ := doublestar.Match(uu.Path, u.Path); ok {
				return u, nil
			}
		}
	}

	return nil, errors.New("unauthorized redirect endpoint")
}
