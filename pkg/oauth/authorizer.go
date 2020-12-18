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

package oauth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ModelRocket/hiro/pkg/api"
)

type (
	// Authorizer is an oauth authorizer interface
	Authorizer interface {
		Authorize(opts ...AuthOption) api.Authorizer
		AuthorizeScope(scope ...string) api.Authorizer
	}

	authorizer struct {
		ctrl             Controller
		permitQueryToken bool
	}

	// AuthOption is an authorizer option
	AuthOption func(a *authOptions)

	// AuthorizerOption is an authorizer option
	AuthorizerOption func(a *authorizer)

	authOptions struct {
		scope    []Scope
		optional bool
	}
)

// NewAuthorizer returns a new oauth authorizer
func NewAuthorizer(ctrl Controller, opts ...AuthorizerOption) Authorizer {
	auth := &authorizer{
		ctrl: ctrl,
	}

	for _, o := range opts {
		o(auth)
	}
	return auth
}

func (a *authorizer) AuthorizeScope(scope ...string) api.Authorizer {
	return a.Authorize(WithScope(MakeScope(scope...)))
}

func (a *authorizer) Authorize(opts ...AuthOption) api.Authorizer {
	o := &authOptions{}

	for _, opt := range opts {
		opt(o)
	}

	return func(r *http.Request) (interface{}, error) {
		ctx := r.Context()

		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer == "" && a.permitQueryToken {
			bearer = r.URL.Query().Get("access_token")
		}

		if bearer == "" {
			if o.optional {
				return ctx, nil
			}

			return nil, fmt.Errorf("%w: token not present", ErrAccessDenied)
		}

		claims, err := ParseBearer(bearer, func(c Claims) (TokenSecret, error) {
			aud, err := a.ctrl.AudienceGet(ctx, c.Audience())
			if err != nil {
				return TokenSecret{}, err
			}
			return aud.Secret(), nil
		})
		if err != nil {
			return nil, err
		}

		return claims, nil
	}
}

// WithScope will create an api.Authorizer with the scope
func WithScope(scope ...Scope) AuthOption {
	return func(o *authOptions) {
		o.scope = scope
	}
}

// WithOptional ignores missing auth tokens, but enforces present tokens
func WithOptional() AuthOption {
	return func(o *authOptions) {
		o.optional = true
	}
}

// WithPermitQueryToken enforces the user roles
func WithPermitQueryToken(permit bool) AuthorizerOption {
	return func(a *authorizer) {
		a.permitQueryToken = permit
	}
}
