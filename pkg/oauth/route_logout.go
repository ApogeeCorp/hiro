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

	"github.com/ModelRocket/hiro/pkg/api"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/gorilla/sessions"
)

type (
	// LogoutParams are the params to log a user out
	LogoutParams struct {
		Audience    string  `json:"audience"`
		ClientID    string  `json:"client_id"`
		RedirectURI *URI    `json:"redirect_uri"`
		State       *string `json:"state"`
	}
)

// Validate validates the params
func (p LogoutParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Audience, validation.Required),
		validation.Field(&p.ClientID, validation.Required),
		validation.Field(&p.RedirectURI, validation.Required, is.RequestURI),
	)
}

func logout(ctx context.Context, params *LogoutParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	log := api.Log(ctx).WithField("operation", "logout")

	// parse the redirect uri
	u, err := params.RedirectURI.Parse()
	if err != nil {
		log.Error(err.Error())

		return ErrAccessDenied.WithError(err)
	}

	aud, err := ctrl.AudienceGet(ctx, params.Audience)
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	client, err := ctrl.ClientGet(ctx, params.ClientID)
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	// authorize this client for the grant, uris
	if err := client.Authorize(
		ctx,
		aud,
		GrantTypeAuthCode,
		[]URI{*params.RedirectURI},
		Scope{},
	); err != nil {
		log.Error(err.Error())

		return ErrAccessDenied.WithError(err)
	}

	store, err := api.SessionManager(ctx).GetStore(ctx, aud.ID())
	if err != nil {
		return api.Redirect(u, api.ErrServerError.WithError(err))
	}

	// check for a session
	r, w := api.Request(ctx)
	session, err := store.Get(r, fmt.Sprintf("hiro-session#%s", aud.ID()))
	if err != nil {
		return api.Redirect(u, api.ErrServerError.WithError(err))
	}

	if !session.IsNew {
		session.Options.MaxAge = -1

		api.SessionManager(ctx).SessionDestroy(ctx, string(session.ID))

		if err := sessions.Save(r, w); err != nil {
			return api.Redirect(u, api.ErrServerError.WithError(err))
		}
	}

	q := u.Query()

	if params.State != nil {
		q.Set("state", *params.State)
	}

	u.RawQuery = q.Encode()

	return api.Redirect(u)
}
