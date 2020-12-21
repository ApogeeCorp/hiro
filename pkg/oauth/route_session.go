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

// Handler implements api.Route
func (r SessionRoute) Handler() interface{} {
	return r
}

// ValidateParameters implements api.Route
func (SessionRoute) ValidateParameters() bool {
	return true
}

// RequireAuth implements api.Route
func (SessionRoute) RequireAuth() bool {
	return true
}

// Scopes implements oauth.Route
func (SessionRoute) Scopes() []Scope {
	return []Scope{MakeScope(ScopeSession)}
}
