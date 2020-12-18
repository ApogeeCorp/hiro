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
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
)

type (
	// Authorizer is an oauth authorizer interface
	Authorizer interface {
		Authorize(opts ...AuthOption) api.Authorizer
		AuthorizeScope(scope ...string) api.Authorizer
	}

	authorizer struct {
		ctrl              Controller
		permitQueryToken  bool
		permitQueryBearer bool
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

	return func(r *http.Request) (api.Principal, error) {
		var token Token
		var err error
		var isQuery bool

		ctx := r.Context()

		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer == "" {
			bearer = r.URL.Query().Get("access_token")
			isQuery = true
		}

		if bearer == "" {
			if o.optional {
				return nil, api.ErrAuthUnacceptable
			}

			return nil, fmt.Errorf("%w: token not present", ErrAccessDenied)
		}

		// check for a token id
		if isQuery && len(bearer) == 22 && a.permitQueryToken {
			token, err = a.ctrl.TokenGet(ctx, bearer)
			if err != nil {
				return nil, ErrAccessDenied.WithError(err)
			}

			if token.RevokedAt != nil {
				return nil, ErrRevokedToken
			} else if token.ExpiresAt != nil && token.ExpiresAt.Time().Before(time.Now()) {
				return nil, ErrExpiredToken
			}
		} else {
			if isQuery && !a.permitQueryBearer {
				return nil, ErrAccessDenied.WithDetail("access token not permited in query")
			}
			token, err = ParseBearer(bearer, func(c Claims) (TokenSecret, error) {
				aud, err := a.ctrl.AudienceGet(ctx, c.Audience())
				if err != nil {
					return TokenSecret{}, err
				}
				return aud.Secret(), nil
			})
			if err != nil {
				return nil, err
			}
		}

		// Identity tokens cannot be used for access
		if token.Use == TokenUseIdentity {
			return nil, api.ErrAuthUnacceptable
		}

		for _, s := range o.scope {
			if token.Scope.Every(s...) {
				return token, nil
			}
		}

		return nil, api.ErrForbidden
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

// WithPermitQueryToken allows token ids to be passed in the query supporting persistent tokens
func WithPermitQueryToken(permit bool) AuthorizerOption {
	return func(a *authorizer) {
		a.permitQueryToken = permit
	}
}

// WithPermitQueryBearer allows full bearer tokens to be passed in to the query
func WithPermitQueryBearer(permit bool) AuthorizerOption {
	return func(a *authorizer) {
		a.permitQueryBearer = permit
	}
}
