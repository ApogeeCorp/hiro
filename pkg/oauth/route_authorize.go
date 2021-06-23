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
	"context"
	"fmt"
	"net/http"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/safe"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// AuthorizeParams contains all the bound params for the authorize operation
	AuthorizeParams struct {
		AppURI              string               `json:"app_uri"`
		Audience            string               `json:"audience"`
		ClientID            string               `json:"client_id"`
		CodeChallenge       PKCEChallenge        `json:"code_challenge"`
		CodeChallengeMethod *PKCEChallengeMethod `json:"code_challenge_method,omitempty"`
		RedirectURI         string               `json:"redirect_uri"`
		ResponseType        string               `json:"response_type"`
		Scope               Scope                `json:"scope"`
		State               *string              `json:"state,omitempty"`
	}

	// AuthorizeRoute is the authorize route handler
	AuthorizeRoute func(ctx context.Context, params *AuthorizeParams) api.Responder
)

var (
	// DefaultCodeChallengeMethod is the only challenge method
	DefaultCodeChallengeMethod = "S256"
)

const (
	// RequestTokenParam is the name of the request token parameter passed on redirect from /authorize
	RequestTokenParam = "request_token"
)

// Validate validates the params
func (p AuthorizeParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.AppURI, validation.Required, is.RequestURI),
		validation.Field(&p.Audience, validation.Required),
		validation.Field(&p.ClientID, validation.Required),
		validation.Field(&p.CodeChallenge, validation.Required),
		validation.Field(&p.CodeChallengeMethod, validation.NilOrNotEmpty),
		validation.Field(&p.RedirectURI, validation.Required, is.RequestURI),
		validation.Field(&p.ResponseType, validation.Required, validation.In("code")),
		validation.Field(&p.Scope, validation.NilOrNotEmpty),
	)
}

func authorize(ctx context.Context, params *AuthorizeParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	// ensure this is a valid client
	client, err := ctrl.ClientGet(ctx, ClientGetInput{
		Audience: params.Audience,
		ClientID: params.ClientID,
	})
	if err != nil {
		return ErrUnauthorized.WithError(ErrClientNotFound)
	}

	// validate the redirect uri
	rdrURI, err := EnsureURI(ctx, params.RedirectURI, client.RedirectEndpoints())
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	// validate the app uri
	appURI, err := EnsureURI(ctx, params.AppURI, client.ApplicationEndpoints())
	if err != nil {
		return api.Redirect(rdrURI).WithError(err)
	}

	// ensure this client is allowed authorization code grant
	if !client.AuthorizedGrants().Contains(GrantTypeAuthCode) {
		return api.Redirect(rdrURI).WithError(ErrUnauthorizedClient)
	}

	// check the scope
	if len(params.Scope) > 0 {
		if params.Scope.Contains(ScopeEmailVerify) || params.Scope.Contains(ScopePhoneVerify) {
			return api.Redirect(rdrURI).WithError(ErrInvalidScope)
		}

		if !client.Permissions().Every(params.Scope...) {
			return api.Redirect(rdrURI).WithError(ErrForbidden)
		}
	}

	store, err := api.SessionManager(ctx).GetStore(ctx, params.Audience)
	if err != nil {
		return api.Redirect(rdrURI).WithError(err)
	}

	// check for a session
	r, _ := api.Request(ctx)
	session, err := store.Get(r, fmt.Sprintf("%s%s", SessionPrefix, params.Audience))
	if err != nil {
		return api.Redirect(rdrURI).WithError(err)
	}

	if !session.IsNew {
		if sub, ok := session.Values["sub"].(string); ok {
			// create a new auth code
			code, err := ctrl.RequestTokenCreate(ctx, RequestToken{
				Type:                RequestTokenTypeAuthCode,
				Audience:            params.Audience,
				ClientID:            params.ClientID,
				Subject:             &sub,
				Scope:               params.Scope,
				CodeChallenge:       params.CodeChallenge,
				CodeChallengeMethod: PKCEChallengeMethod(safe.String(params.CodeChallengeMethod, PKCEChallengeMethodS256)),
				AppURI:              &params.AppURI,
				RedirectURI:         &params.RedirectURI,
			})
			if err != nil {
				api.Redirect(rdrURI).WithError(err)
			}

			// parse the redirect uri
			q := rdrURI.Query()
			q.Set("code", code)

			if params.State != nil {
				q.Set("state", *params.State)
			}
			rdrURI.RawQuery = q.Encode()

			return api.Redirect(rdrURI)
		}
	}

	// create a new login request
	token, err := ctrl.RequestTokenCreate(ctx, RequestToken{
		Type:                RequestTokenTypeLogin,
		Audience:            params.Audience,
		ClientID:            params.ClientID,
		Scope:               params.Scope,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: PKCEChallengeMethod(safe.String(params.CodeChallengeMethod, PKCEChallengeMethodS256)),
		AppURI:              &params.AppURI,
		RedirectURI:         &params.RedirectURI,
		State:               params.State,
	})
	if err != nil {
		return api.Redirect(rdrURI).WithError(err)
	}

	q := appURI.Query()
	q.Set(RequestTokenParam, token)

	appURI.RawQuery = q.Encode()

	return api.Redirect(appURI)
}

// Name implements api.Route
func (AuthorizeRoute) Name() string {
	return "authorize"
}

// Methods implements api.Route
func (AuthorizeRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (AuthorizeRoute) Path() string {
	return "/authorize"
}

// Validate implements validation.Validatable
func (AuthorizeRoute) Validate(params validation.Validatable) error {
	return params.Validate()
}
