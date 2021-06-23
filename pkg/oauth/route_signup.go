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
	"net/url"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/oauth/openid"
	"github.com/ModelRocket/hiro/pkg/ptr"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// SignupParams are used in the signup route
	SignupParams struct {
		Login        string          `json:"login"`
		Password     *string         `json:"password,omitempty"`
		InviteToken  *string         `json:"invite_token,omitempty"`
		RequestToken string          `json:"request_token"`
		CodeVerifier string          `json:"code_verifier"`
		Profile      *openid.Profile `json:"profile,omitempty"`
	}

	// SignupRoute is the signup handler
	SignupRoute func(ctx context.Context, params *SignupParams) api.Responder
)

// Validate validates SignupParams
func (p SignupParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Login, validation.Required),
		validation.Field(&p.Password, validation.NilOrNotEmpty),
		validation.Field(&p.InviteToken, validation.NilOrNotEmpty),
		validation.Field(&p.RequestToken, validation.Required),
		validation.Field(&p.CodeVerifier, validation.Required),
	)
}

func signup(ctx context.Context, params *SignupParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	req, err := ctrl.RequestTokenGet(ctx, RequestTokenGetInput{
		TokenID:   params.RequestToken,
		TokenType: RequestTokenTypePtr(RequestTokenTypeLogin),
	})
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	// parse the app uri
	appURI, err := url.Parse(*req.AppURI)
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	if req.Expired() {
		return api.Redirect(appURI).WithError(ErrExpiredToken)
	}

	if err := req.CodeChallenge.Verify(params.CodeVerifier); err != nil {
		return api.Redirect(appURI).WithError(ErrUnauthorized.WithError(err))
	}

	var invite *RequestToken

	if params.InviteToken != nil {
		inv, err := ctrl.RequestTokenGet(ctx, RequestTokenGetInput{
			TokenID:   *params.InviteToken,
			TokenType: RequestTokenTypePtr(RequestTokenTypeInvite),
		})
		if err != nil {
			return api.Redirect(appURI).WithError(err)
		}

		invite = &inv
	}

	user, err := ctrl.UserCreate(ctx, UserCreateInput{
		Audience: req.Audience,
		Login:    params.Login,
		Password: params.Password,
		Profile:  params.Profile,
		Invite:   invite,
	})
	if err != nil {
		return api.Redirect(appURI).WithError(err)
	}

	if len(req.Scope) == 0 {
		req.Scope = user.Permissions()
	}

	if !user.Permissions().Every(req.Scope...) {
		return api.Redirect(appURI).WithError(ErrForbidden)
	}

	store, err := api.SessionManager(ctx).GetStore(ctx, req.Audience, user.ID())
	if err != nil {
		return api.Redirect(appURI).WithError(err)
	}

	// create the session
	r, w := api.Request(ctx)
	session, err := store.Get(r, fmt.Sprintf("%s%s", SessionPrefix, req.Audience))
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

	// parse the redirect uri
	rdrURI, err := url.Parse(*req.RedirectURI)
	if err != nil {
		return api.Redirect(appURI).WithError(err)
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
func (SignupRoute) Name() string {
	return "signup"
}

// Methods implements api.Route
func (SignupRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (SignupRoute) Path() string {
	return "/signup"
}
