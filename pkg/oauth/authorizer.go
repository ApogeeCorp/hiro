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

package oauth

import (
	"fmt"
	"net/http"
	"strings"

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

	return &a
}

func (a authorizer) Authorize(r *http.Request, rt api.Route) (api.Principal, error) {
	var token Token
	var err error
	var isQuery bool

	o, ok := rt.(Route)
	if !ok {
		return nil, api.ErrAuthUnacceptable
	}

	ctx := r.Context()

	var ctrl Controller

	switch c := api.Context(ctx).(type) {
	case Controller:
		ctrl = c
	default:
		return nil, api.ErrAuthUnacceptable
	}

	if ctrl == nil {
		return nil, api.ErrAuthUnacceptable
	}

	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == "" {
		bearer = r.URL.Query().Get("access_token")
		isQuery = true
	}

	if bearer == "" {
		return nil, fmt.Errorf("%w: token not present", ErrUnauthorized)
	}

	// check for a token id
	if isQuery && len(bearer) == 22 && a.permitQueryToken {
		token, err = ctrl.TokenGet(ctx, TokenGetInput{TokenID: bearer})
		if err != nil {
			return nil, ErrUnauthorized.WithError(err)
		}

		if token.RevokedAt != nil {
			return nil, ErrRevokedToken
		} else if token.Expired() {
			return nil, ErrExpiredToken
		}
	} else {
		if isQuery && !a.permitQueryBearer {
			return nil, ErrUnauthorized.WithDetail("access token not permited in query")
		}
		token, err = ParseBearer(bearer, func(kid string, c Claims) (TokenSecret, error) {
			client, err := ctrl.ClientGet(ctx, ClientGetInput{
				Audience: c.Audience(),
				ClientID: c.ClientID(),
			})
			if err != nil {
				return nil, err
			}

			if client.TokenSecret().ID() == kid {
				return client.TokenSecret(), nil
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

	if o.Scopes().Check(token.Scope) {
		return token, nil
	}

	return nil, api.ErrForbidden.WithDetail("insufficent token scope", o.Scopes())
}

func (a authorizer) CredentialType() api.CredentialType {
	return api.CredentialTypeBearer
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
