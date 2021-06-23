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
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/ptr"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// LoginParams contains all the bound params for the login operation
	LoginParams struct {
		Login        string `json:"login"`
		Password     string `json:"password"`
		RequestToken string `json:"request_token"`
		CodeVerifier string `json:"code_verifier"`
	}

	// LoginRoute is the login route handler
	LoginRoute func(ctx context.Context, params *LoginParams) api.Responder
)

// Validate validates LoginParams
func (p LoginParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Login, validation.Required),
		validation.Field(&p.Password, validation.Required),
		validation.Field(&p.RequestToken, validation.Required),
		validation.Field(&p.CodeVerifier, validation.Required),
	)
}

func login(ctx context.Context, params *LoginParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	req, err := ctrl.RequestTokenGet(ctx, RequestTokenGetInput{
		TokenID:   params.RequestToken,
		TokenType: RequestTokenTypePtr(RequestTokenTypeLogin),
	})
	if err != nil {
		var e ErrTooManyLoginAttempts

		if errors.As(err, &e) {
			if _, err := ctrl.UserUpdate(ctx, UserUpdateInput{
				Audience: req.Audience,
				Login:    &params.Login,
				Lockout:  ptr.True,
			}); err != nil {
				return api.Error(err)
			}

			return e
		}

		return ErrUnauthorized.WithError(err)
	}

	// parse the app uri, errors go back to the app
	appURI, err := url.Parse(*req.AppURI)
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	if req.Expired() {
		return api.Redirect(appURI).WithError(ErrExpiredToken)
	}

	if err := req.CodeChallenge.Verify(params.CodeVerifier); err != nil {
		return api.Redirect(appURI).WithError(err)
	}

	// ensure the request audience is valid
	aud, err := ctrl.AudienceGet(ctx, AudienceGetInput{Audience: req.Audience})
	if err != nil {
		return api.Redirect(appURI).WithError(err)
	}

	userGet := UserGetInput{
		Audience: req.Audience,
		Login:    &params.Login,
	}

	if req.Passcode != nil {
		if params.Password != *req.Passcode {
			return api.Redirect(appURI).WithError(ErrUnauthorized)
		}
	} else {
		userGet.Password = &params.Password
	}
	user, err := ctrl.UserGet(ctx, userGet)
	if err != nil {
		return api.Redirect(appURI).WithError(err)
	}

	if len(req.Scope) == 0 {
		req.Scope = user.Permissions()
	}

	if !user.Permissions().Every(req.Scope...) {
		return api.Redirect(appURI).WithError(ErrForbidden)
	}

	store, err := api.SessionManager(ctx).GetStore(ctx, aud.ID(), user.ID())
	if err != nil {
		return api.Redirect(appURI).WithError(err)
	}

	// create the session
	r, w := api.Request(ctx)
	session, err := store.Get(r, fmt.Sprintf("%s%s", SessionPrefix, aud.ID()))
	if err != nil {
		return api.Redirect(appURI).WithError(err)
	}

	session.Values["sub"] = user.ID()

	if err := session.Save(r, w); err != nil {
		return api.Redirect(appURI).WithError(err)
	}

	// create a new auth code
	code, err := ctrl.RequestTokenCreate(ctx, RequestToken{
		Type:                RequestTokenTypeAuthCode,
		Audience:            req.Audience,
		ClientID:            req.ClientID,
		Subject:             ptr.String(user.ID()),
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		RedirectURI:         req.RedirectURI,
	})
	if err != nil {
		api.Redirect(appURI).WithError(err)
	}

	// parse and redirect to the final destination
	rdrURI, err := url.Parse(*req.RedirectURI)
	if err != nil {
		api.Redirect(appURI).WithError(err)
	}
	q := rdrURI.Query()
	q.Set("code", code)

	if req.State != nil {
		q.Set("state", *req.State)
	}
	rdrURI.RawQuery = q.Encode()

	return api.Redirect(rdrURI)
}

// Name implements api.Route
func (LoginRoute) Name() string {
	return "login"
}

// Methods implements api.Route
func (LoginRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (LoginRoute) Path() string {
	return "/login"
}
