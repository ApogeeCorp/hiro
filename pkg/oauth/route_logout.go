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
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/gorilla/sessions"
)

type (
	// LogoutParams are the params to log a user out
	LogoutParams struct {
		Audience              string  `json:"audience"`
		ClientID              string  `json:"client_id"`
		RedirectURI           *URI    `json:"redirect_uri"`
		PostLogoutRedirectURI *URI    `json:"post_logout_redirect_uri,omitempty"`
		State                 *string `json:"state"`
	}

	// LogoutRoute is the logout route handler
	LogoutRoute func(ctx context.Context, params *LogoutParams) api.Responder
)

// Validate validates the params
func (p LogoutParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Audience, validation.Required),
		validation.Field(&p.ClientID, validation.Required),
		validation.Field(&p.RedirectURI, validation.When(p.PostLogoutRedirectURI == nil, validation.Required), is.RequestURI),
		validation.Field(&p.PostLogoutRedirectURI, validation.When(p.RedirectURI == nil, validation.Required), is.RequestURI),
	)
}

func logout(ctx context.Context, params *LogoutParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	log := api.Log(ctx).WithField("operation", "logout")

	if params.RedirectURI == nil {
		params.RedirectURI = params.PostLogoutRedirectURI
	}
	
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

// Name implements api.Route
func (LogoutRoute) Name() string {
	return "logout"
}

// Methods implements api.Route
func (LogoutRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (LogoutRoute) Path() string {
	return "/logout"
}
