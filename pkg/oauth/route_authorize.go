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
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/safe"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// AuthorizeParams contains all the bound params for the authorize operation
	AuthorizeParams struct {
		AppURI              URI                  `json:"app_uri"`
		Audience            string               `json:"audience"`
		ClientID            string               `json:"client_id"`
		CodeChallenge       PKCEChallenge        `json:"code_challenge"`
		CodeChallengeMethod *PKCEChallengeMethod `json:"code_challenge_method"`
		RedirectURI         *URI                 `json:"redirect_uri"`
		ResponseType        string               `json:"response_type"`
		Scope               Scope                `json:"scope"`
		State               *string              `json:"state"`
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
		validation.Field(&p.RedirectURI, validation.NilOrNotEmpty, is.RequestURI),
		validation.Field(&p.ResponseType, validation.Required, validation.In("code")),
		validation.Field(&p.Scope, validation.NilOrNotEmpty),
	)
}

func authorize(ctx context.Context, params *AuthorizeParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	log := api.Log(ctx).WithField("operation", "authorize")

	// ensure the audience is valid
	aud, err := ctrl.AudienceGet(ctx, params.Audience)
	if err != nil {
		log.Error(err.Error())

		return ErrAccessDenied.WithError(err)
	}

	// ensure this is a valid client
	client, err := ctrl.ClientGet(ctx, params.ClientID)
	if err != nil {
		log.Error(err.Error())

		return ErrAccessDenied.WithError(err)
	}

	// authorize this client for the grant, uris, and scope
	uris := []URI{params.AppURI}
	if params.RedirectURI != nil {
		uris = append(uris, *params.RedirectURI)
	}

	// User's cannot request verification scopes
	params.Scope = params.Scope.Without(ScopeEmailVerify, ScopePhoneVerify)

	if err := client.Authorize(
		ctx,
		aud,
		GrantTypeAuthCode,
		uris,
		params.Scope,
	); err != nil {
		log.Error(err.Error())

		return ErrAccessDenied.WithError(err)
	}

	// parse the api uri
	u, err := params.AppURI.Parse()
	if err != nil {
		log.Error(err.Error())

		return ErrAccessDenied.WithError(err)
	}

	store, err := api.SessionManager(ctx).GetStore(ctx, aud.ID())
	if err != nil {
		return api.ErrServerError.WithError(err)
	}

	// check for a session
	r, _ := api.Request(ctx)
	session, err := store.Get(r, fmt.Sprintf("hiro-session#%s", aud.ID()))
	if err != nil {
		return api.ErrServerError.WithError(err)
	}

	if !session.IsNew {
		if sub, ok := session.Values["sub"].(string); ok {
			// create a new auth code
			code, err := ctrl.RequestTokenCreate(ctx, RequestToken{
				Type:                RequestTokenTypeAuthCode,
				Audience:            string(params.Audience),
				ClientID:            string(params.ClientID),
				Subject:             &sub,
				ExpiresAt:           Time(time.Now().Add(time.Minute * 10)),
				Scope:               params.Scope,
				CodeChallenge:       params.CodeChallenge,
				CodeChallengeMethod: PKCEChallengeMethod(safe.String(params.CodeChallengeMethod, PKCEChallengeMethodS256)),
				AppURI:              &params.AppURI,
				RedirectURI:         params.RedirectURI,
			})
			if err != nil {
				api.Redirect(u).WithError(ErrAccessDenied.WithError(err))
			}

			log.Debugf("auth code %s created", code)

			if params.RedirectURI != nil {
				u, err = params.RedirectURI.Parse()
				if err != nil {
					return ErrAccessDenied.WithError(err)
				}
			}

			// parse the redirect uri
			q := u.Query()
			q.Set("code", code)

			if params.State != nil {
				q.Set("state", *params.State)
			}
			u.RawQuery = q.Encode()

			return api.Redirect(u)
		}
	}

	// create a new login request
	token, err := ctrl.RequestTokenCreate(ctx, RequestToken{
		Type:                RequestTokenTypeLogin,
		Audience:            string(params.Audience),
		ClientID:            string(params.ClientID),
		ExpiresAt:           Time(time.Now().Add(time.Minute * 10)),
		Scope:               params.Scope,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: PKCEChallengeMethod(safe.String(params.CodeChallengeMethod, PKCEChallengeMethodS256)),
		AppURI:              &params.AppURI,
		RedirectURI:         params.RedirectURI,
		State:               params.State,
	})
	if err != nil {
		log.Error(err.Error())

		return api.Redirect(u).WithError(ErrAccessDenied.WithError(err))
	}
	log.Debugf("request token %s created", token)

	q := u.Query()
	q.Set(RequestTokenParam, token)

	u.RawQuery = q.Encode()

	return api.Redirect(u)
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
