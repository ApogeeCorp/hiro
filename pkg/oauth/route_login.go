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
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/types"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// LoginParams contains all the bound params for the login operation
	LoginParams struct {
		Login        string   `json:"login"`
		Password     string   `json:"password"`
		RequestToken types.ID `json:"request_token"`
		CodeVerifier string   `json:"code_verifier"`
	}
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

	log := api.Log(ctx).WithField("operation", "login").WithField("login", params.Login)

	req, err := ctrl.RequestTokenGet(ctx, params.RequestToken)
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	// parse the app uri
	u, err := req.AppURI.Parse()
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	if req.ExpiresAt.Time().Before(time.Now()) {
		return api.Redirect(u, err)
	}

	if req.Type != RequestTokenTypeLogin {
		return api.Redirect(u, ErrInvalidToken.WithDetail("expected token type login"))
	}

	if err := req.CodeChallenge.Verify(params.CodeVerifier); err != nil {
		return api.Redirect(u, ErrAccessDenied.WithError(err))
	}

	// ensure the request audience is valid
	aud, err := ctrl.AudienceGet(ctx, req.Audience.String())
	if err != nil {
		return api.Redirect(u, ErrAccessDenied.WithError(err))
	}

	user, err := ctrl.UserAuthenticate(ctx, params.Login, params.Password)
	if err != nil {
		return api.Redirect(u, ErrAccessDenied.WithError(err))
	}
	log.Debugf("user %s authenticated", user.SubjectID())

	perms := user.Permissions(aud)
	if len(perms) == 0 {
		return ErrAccessDenied.WithMessage("user is not authorized for audience %s", aud.ID())
	}

	if len(req.Scope) == 0 {
		req.Scope = perms
	}

	if !perms.Every(req.Scope...) {
		return ErrAccessDenied.WithMessage("user has insufficient access for request")
	}

	log.Debugf("user %s authorized %s", user.SubjectID(), req.Scope)

	store, err := api.SessionManager(ctx).GetStore(ctx, aud.ID(), user.SubjectID())
	if err != nil {
		return api.ErrServerError.WithError(err)
	}

	// create the session
	r, w := api.Request(ctx)
	session, err := store.Get(r, fmt.Sprintf("hiro-session#%s", aud.ID()))
	if err != nil {
		return api.ErrServerError.WithError(err)
	}

	session.Values["sub"] = user.SubjectID().String()

	if err := session.Save(r, w); err != nil {
		return api.ErrServerError.WithError(err)
	}

	// create a new auth code
	code, err := ctrl.RequestTokenCreate(ctx, RequestToken{
		Type:                RequestTokenTypeAuthCode,
		Audience:            req.Audience,
		ClientID:            req.ClientID,
		Subject:             user.SubjectID(),
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
		return api.NewResponse()
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
