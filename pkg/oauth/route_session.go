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
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/safe"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// SessionParams is the session request parameters
	SessionParams struct {
		RequestToken string  `json:"request_token"`
		RedirectURI  *URI    `json:"redirect_ur"`
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

	log := api.Log(ctx).WithField("operation", "session").WithField("token", params.RequestToken)

	ctrl := api.Context(ctx).(Controller)

	api.RequirePrincipal(ctx, &token, api.PrincipalTypeUser)

	if err := ctrl.TokenRevoke(ctx, token.ID); err != nil {
		return api.Error(err)
	}

	req, err := ctrl.RequestTokenGet(ctx, params.RequestToken, RequestTokenTypeLogin)
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	// parse the app uri
	u, err := req.AppURI.Parse()
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	// ensure the request audience is valid
	aud, err := ctrl.AudienceGet(ctx, req.Audience)
	if err != nil {
		return api.Redirect(u, ErrAccessDenied.WithError(err))
	}

	user, err := ctrl.UserGet(ctx, safe.String(req.Subject))
	if err != nil {
		return api.Redirect(u, ErrAccessDenied.WithError(err))
	}
	log.Debugf("user %s authenticated", user.Subject())

	perms := user.Permissions(aud)
	if len(perms) == 0 {
		return ErrAccessDenied.WithMessage("user is not authorized for audience %s", aud.ID())
	}

	if len(req.Scope) == 0 {
		req.Scope = perms
	}

	// we ignore some special scopes that are granted to the user on the fly
	checkScope := req.Scope.Without(ScopePassword, ScopeSession, ScopeEmailVerify, ScopePhoneVerify)

	if !perms.Every(checkScope...) {
		return ErrAccessDenied.WithMessage("user has insufficient access for request")
	}

	log.Debugf("user %s authorized %s", user.Subject(), req.Scope)

	store, err := api.SessionManager(ctx).GetStore(ctx, aud.ID(), user.Subject())
	if err != nil {
		return api.ErrServerError.WithError(err)
	}

	// create the session
	r, w := api.Request(ctx)
	session, err := store.Get(r, fmt.Sprintf("hiro-session#%s", aud.ID()))
	if err != nil {
		return api.ErrServerError.WithError(err)
	}

	session.Values["sub"] = user.Subject()

	if err := session.Save(r, w); err != nil {
		return api.ErrServerError.WithError(err)
	}

	if params.RedirectURI != nil {
		client, err := ctrl.ClientGet(ctx, req.ClientID)
		if err != nil {
			return api.ErrServerError.WithError(err)
		}

		if err := client.Authorize(ctx, aud, GrantTypeNone, []URI{*params.RedirectURI}); err != nil {
			return ErrAccessDenied.WithError(err)
		}

		req.RedirectURI = params.RedirectURI
	}

	// create a new auth code
	code, err := ctrl.RequestTokenCreate(ctx, RequestToken{
		Type:                RequestTokenTypeAuthCode,
		Audience:            req.Audience,
		ClientID:            req.ClientID,
		Subject:             ptr.String(user.Subject()),
		ExpiresAt:           Time(time.Now().Add(time.Minute * 10)),
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		RedirectURI:         req.RedirectURI,
	})
	if err != nil {
		api.Redirect(u, ErrAccessDenied.WithError(err))
	}
	log.Debugf("auth code %s created", code)

	if req.RedirectURI == nil {
		return api.NewResponse().WithStatus(http.StatusNoContent)
	}

	// parse the redirect uri
	u, err = req.RedirectURI.Parse()
	if err != nil {
		return ErrAccessDenied.WithError(err)
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
