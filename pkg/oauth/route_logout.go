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
		RedirectURI           *string `json:"redirect_uri"`
		PostLogoutRedirectURI *string `json:"post_logout_redirect_uri,omitempty"`
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

	// this is to support openid connect wonky params
	if params.RedirectURI == nil {
		params.RedirectURI = params.PostLogoutRedirectURI
	}

	client, err := ctrl.ClientGet(ctx, ClientGetInput{
		Audience: params.Audience,
		ClientID: params.ClientID,
	})
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	// validate the redirect uri
	u, err := EnsureURI(ctx, *params.RedirectURI, client.RedirectEndpoints())
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	store, err := api.SessionManager(ctx).GetStore(ctx, params.Audience)
	if err != nil {
		return api.Redirect(u).WithError(err)
	}

	// check for a session
	r, w := api.Request(ctx)
	session, err := store.Get(r, fmt.Sprintf("%s%s", SessionPrefix, params.Audience))
	if err != nil {
		return api.Redirect(u).WithError(err)
	}

	if !session.IsNew {
		session.Options.MaxAge = -1

		api.SessionManager(ctx).SessionDestroy(ctx, string(session.ID))

		if err := sessions.Save(r, w); err != nil {
			return api.Redirect(u).WithError(err)
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
