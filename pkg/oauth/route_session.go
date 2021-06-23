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
	"github.com/ModelRocket/hiro/pkg/ptr"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// SessionParams is the session request parameters
	SessionParams struct {
		RequestToken string  `json:"request_token"`
		RedirectURI  *string `json:"redirect_uri,omitempty"`
		State        *string `json:"state,omitempty"`
	}

	// SessionRoute is the session handler
	SessionRoute func(ctx context.Context, params *SessionParams) api.Responder
)

// Validate validates the SessionParams struct
func (p SessionParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.RequestToken, validation.Required),
		validation.Field(&p.RedirectURI, validation.NilOrNotEmpty, is.RequestURI))
}

func session(ctx context.Context, params *SessionParams) api.Responder {
	var token Token

	ctrl := api.Context(ctx).(Controller)

	api.RequirePrincipal(ctx, &token, api.PrincipalTypeUser)

	if err := ctrl.TokenRevoke(ctx, TokenRevokeInput{TokenID: &token.ID}); err != nil {
		return api.Error(err)
	}

	req, err := ctrl.RequestTokenGet(ctx, RequestTokenGetInput{
		TokenID:   params.RequestToken,
		TokenType: RequestTokenTypePtr(RequestTokenTypeLogin),
	})
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	// parse the original app uri
	u, err := url.Parse(*req.AppURI)
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	if req.Expired() {
		api.Redirect(u).WithError(ErrExpiredToken)
	}

	user, err := ctrl.UserGet(ctx, UserGetInput{
		Audience: req.Audience,
		Subject:  req.Subject,
	})
	if err != nil {
		return api.Redirect(u).WithError(ErrUnauthorized.WithError(err))
	}

	if len(req.Scope) == 0 {
		req.Scope = user.Permissions()
	}

	// we ignore some special scopes that are granted to the user on the fly
	checkScope := req.Scope.Without(ScopePassword, ScopeSession, ScopeEmailVerify, ScopePhoneVerify)

	if !user.Permissions().Every(checkScope...) {
		api.Redirect(u).WithError(ErrForbidden)
	}

	store, err := api.SessionManager(ctx).GetStore(ctx, req.Audience, user.ID())
	if err != nil {
		api.Redirect(u).WithError(err)
	}

	// create the session
	r, w := api.Request(ctx)
	session, err := store.Get(r, fmt.Sprintf("%s%s", SessionPrefix, req.Audience))
	if err != nil {
		api.Redirect(u).WithError(err)
	}

	session.Values["sub"] = user.ID()

	if err := session.Save(r, w); err != nil {
		api.Redirect(u).WithError(err)
	}

	if params.RedirectURI != nil {
		client, err := ctrl.ClientGet(ctx, ClientGetInput{
			Audience: req.Audience,
			ClientID: req.ClientID,
		})
		if err != nil {
			api.Redirect(u).WithError(err)
		}

		u, err := EnsureURI(ctx, *params.RedirectURI, client.RedirectEndpoints())
		if err != nil {
			api.Redirect(u).WithError(err)
		}

		req.RedirectURI = ptr.String(u.String())
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
		api.Redirect(u).WithError(err)
	}

	if req.RedirectURI == nil {
		return api.NewResponse().WithStatus(http.StatusNoContent)
	}

	// parse the redirect uri
	u, err = url.Parse(*req.RedirectURI)
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}
	q := u.Query()
	q.Set("code", code)

	if req.State != nil {
		q.Set("state", *req.State)
	}
	u.RawQuery = q.Encode()

	return api.Redirect(u)
}

// Name implements api.Route
func (SessionRoute) Name() string {
	return "authorize"
}

// Methods implements api.Route
func (SessionRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (SessionRoute) Path() string {
	return "/session"
}

// RequireAuth implements the api.AuthorizedRoute
func (SessionRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (SessionRoute) Scopes() ScopeList {
	return BuildScope(ScopeSession)
}
