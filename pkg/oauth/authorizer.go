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
	authorizer struct {
		permitQueryToken  bool
		permitQueryBearer bool
	}

	// AuthorizerOption is an authorizer option
	AuthorizerOption func(a *authorizer)
)

// Authorizer returns a oauth api.Authorizer
func Authorizer(opts ...AuthorizerOption) api.Authorizer {
	a := authorizer{}

	for _, opt := range opts {
		opt(&a)
	}

	return func(r *http.Request, rt api.Route) (api.Principal, error) {
		var token Token
		var err error
		var isQuery bool

		o, ok := rt.(Route)
		if !ok {
			return nil, api.ErrAuthUnacceptable
		}

		ctx := r.Context()

		ctrl, ok := api.Context(ctx).(Controller)
		if !ok {
			return nil, api.ErrAuthUnacceptable
		}

		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer == "" {
			bearer = r.URL.Query().Get("access_token")
			isQuery = true
		}

		if bearer == "" {
			return nil, fmt.Errorf("%w: token not present", ErrAccessDenied)
		}

		// check for a token id
		if isQuery && len(bearer) == 22 && a.permitQueryToken {
			token, err = ctrl.TokenGet(ctx, bearer)
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
			token, err = ParseBearer(bearer, func(kid string, c Claims) (TokenSecret, error) {
				aud, err := ctrl.AudienceGet(ctx, c.Audience())
				if err != nil {
					return nil, err
				}

				for _, s := range aud.Secrets() {
					if string(s.ID()) == kid {
						return s, nil
					}
				}
				
				return nil, ErrKeyNotFound
			})
			if err != nil {
				return nil, err
			}
		}

		// Identity tokens cannot be used for access
		if token.Use == TokenUseIdentity {
			return nil, api.ErrAuthUnacceptable
		}

		for _, s := range o.Scopes() {
			if token.Scope.Every(s...) {
				return token, nil
			}
		}

		return nil, api.ErrForbidden
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
