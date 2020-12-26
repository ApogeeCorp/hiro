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
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"path"
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/ptr"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// PasswordCreateParams is the input to the password get route
	PasswordCreateParams struct {
		Login        string                `json:"login"`
		Notify       []NotificationChannel `json:"notify"`
		Type         PasswordType          `json:"type"`
		RequestToken string                `json:"request_token"`
		RedirectURI  *URI                  `json:"redirect_uri,omitempty"`
		CodeVerifier string                `json:"code_verifier"`
	}

	// PasswordCreateRoute is the password create handler
	PasswordCreateRoute func(ctx context.Context, params *PasswordCreateParams) api.Responder

	// PasswordUpdateParams are used by the password update route
	PasswordUpdateParams struct {
		Password    string `json:"password"`
		ResetToken  string `json:"reset_token"`
		RedirectURI *URI   `json:"redirect_uri"`
	}

	// PasswordUpdateRoute is the password update handler
	PasswordUpdateRoute func(ctx context.Context, params *PasswordUpdateParams) api.Responder

	// PasswordType defines a password type
	PasswordType string

	// PasswordNotification is a password notification interface
	PasswordNotification interface {
		Notification
		PasswordType() PasswordType
		Code() string
	}

	passwordNotification struct {
		login        string
		passwordType PasswordType
		uri          *URI
		code         string
		notify       []NotificationChannel
	}
)

const (
	// PasswordTypeLink is a magic password link
	PasswordTypeLink PasswordType = "link"

	// PasswordTypeCode is a one-time use password code
	PasswordTypeCode PasswordType = "code"

	// PasswordTypeReset sends both a link with the password scope and a code
	PasswordTypeReset PasswordType = "reset"
)

var (
	passcodeAlpha = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}
)

// Validate validates the PasswordType
func (p PasswordType) Validate() error {
	return validation.Validate(string(p), validation.In("link", "code", "reset"))
}

// Validate validates PasswordGetInput
func (p PasswordCreateParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Login, validation.Required),
		validation.Field(&p.Type, validation.Required),
		validation.Field(&p.Notify, validation.Required, validation.Each(validation.In(NotificationChannelEmail, NotificationChannelPhone))),
		validation.Field(&p.RequestToken, validation.Required),
		validation.Field(&p.RedirectURI, validation.NilOrNotEmpty, is.RequestURI),
		validation.Field(&p.CodeVerifier, validation.Required),
	)
}

// Validate validates PasswordGetInput
func (p PasswordUpdateParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Password, validation.Required),
		validation.Field(&p.ResetToken, validation.Required),
		validation.Field(&p.RedirectURI, validation.NilOrNotEmpty, is.RequestURI),
	)
}

func passwordCreate(ctx context.Context, params *PasswordCreateParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	log := api.Log(ctx).WithField("operation", "passwordCreate").WithField("login", params.Login)

	req, err := ctrl.RequestTokenGet(ctx, params.RequestToken, RequestTokenTypeLogin)
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

	if err := req.CodeChallenge.Verify(params.CodeVerifier); err != nil {
		return api.Redirect(u, ErrAccessDenied.WithError(err))
	}

	user, err := ctrl.UserGet(ctx, params.Login)
	if err != nil {
		return api.Redirect(u, ErrAccessDenied.WithError(err))
	}
	req.Subject = ptr.String(user.Subject())

	// The new token is for sessions which should be one time use
	req.Type = RequestTokenTypeSession

	// Links are cood for 1 hour, codes are good for 10 minutes
	if params.Type.IsLink() {
		req.ExpiresAt = Time(time.Now().Add(time.Hour * 1))
	} else {
		req.ExpiresAt = Time(time.Now().Add(time.Minute * 10))
	}

	if params.Type == PasswordTypeCode {
		// generate a simple OTP for the this request
		req.Passcode = ptr.String(generatePasscode(6))

	} else if params.Type == PasswordTypeReset {
		// the user will need the password reset scope for thier magic link token
		req.Scope = append(req.Scope, ScopePassword)

		// create a password reset token that the user will use to change their password
		passToken, err := ctrl.RequestTokenCreate(ctx, RequestToken{
			Type:      RequestTokenTypeVerify,
			Subject:   req.Subject,
			ClientID:  req.ClientID,
			Audience:  req.Audience,
			ExpiresAt: req.ExpiresAt,
		})
		if err != nil {
			return api.Redirect(u, ErrAccessDenied.WithError(err))
		}

		req.Passcode = &passToken
	}

	reqToken, err := ctrl.RequestTokenCreate(ctx, req)
	if err != nil {
		return api.Redirect(u, ErrAccessDenied.WithError(err))
	}

	note := &passwordNotification{
		login:        params.Login,
		passwordType: params.Type,
		notify:       params.Notify,
		code:         *req.Passcode,
	}

	if params.Type.IsLink() {
		// link and resets need a magic session link with an access token
		r, _ := api.Request(ctx)

		token, err := ctrl.TokenCreate(ctx, Token{
			Issuer:    issuer(ctx, req.Audience),
			Subject:   ptr.String(user.Subject()),
			Audience:  req.Audience,
			ClientID:  req.ClientID,
			Use:       TokenUseAccess,
			ExpiresAt: Time(time.Now().Add(time.Hour * 1)).Ptr(),
			Revokable: true,
			Scope:     Scope{ScopeSession},
		})
		if err != nil {
			log.Error(err.Error())

			return api.Redirect(u, ErrAccessDenied.WithError(err))
		}

		link, err := URI(
			fmt.Sprintf("https://%s%s",
				r.Host,
				path.Clean(path.Join(path.Dir(r.URL.Path), "session")))).Parse()
		if err != nil {
			log.Error(err.Error())

			return api.Redirect(u, ErrAccessDenied.WithError(err))
		}

		q := link.Query()
		q.Set("access_token", token.ID)
		q.Set("request_token", reqToken)

		link.RawQuery = q.Encode()

		note.uri = URI(link.String()).Ptr()
	}

	if err := ctrl.UserNotify(ctx, note); err != nil {
		log.Error(err.Error())

		return api.Redirect(u, ErrAccessDenied.WithError(err))
	}

	if params.RedirectURI != nil {
		aud, err := ctrl.AudienceGet(ctx, req.Audience)
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}

		client, err := ctrl.ClientGet(ctx, req.ClientID)
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}

		if err := client.Authorize(ctx, aud, GrantTypeNone, []URI{*params.RedirectURI}); err != nil {
			return ErrAccessDenied.WithError(err)
		}

		req.RedirectURI = params.RedirectURI
	}

	u, err = req.RedirectURI.Parse()
	if err != nil {
		return api.Redirect(u, ErrAccessDenied.WithError(err))
	}
	q := u.Query()
	if !params.Type.IsLink() {
		q.Set("request_token", reqToken)
	}
	if req.State != nil {
		q.Set("state", *req.State)
	}
	u.RawQuery = q.Encode()

	return api.Redirect(u)
}

// Name implements api.Route
func (PasswordCreateRoute) Name() string {
	return "passwordCreate"
}

// Methods implements api.Route
func (PasswordCreateRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (PasswordCreateRoute) Path() string {
	return "/password"
}

func passwordUpdate(ctx context.Context, params *PasswordUpdateParams) api.Responder {
	var token Token

	ctrl := api.Context(ctx).(Controller)

	api.RequirePrincipal(ctx, &token, api.PrincipalTypeUser)

	log := api.Log(ctx).
		WithField("operation", "passwordUpdate").
		WithField("sub", token.Subject)

	req, err := ctrl.RequestTokenGet(ctx, params.ResetToken, RequestTokenTypeVerify)
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	if *req.Subject != *token.Subject {
		return ErrAccessDenied.WithDetail("subject does not match")
	}

	log.Debug("updating user password")

	if err := ctrl.UserSetPassword(ctx, *token.Subject, params.Password); err != nil {
		return api.Error(err)
	}

	if params.RedirectURI != nil {
		aud, err := ctrl.AudienceGet(ctx, req.Audience)
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}

		client, err := ctrl.ClientGet(ctx, req.ClientID)
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}

		if err := client.Authorize(ctx, aud, GrantTypeNone, []URI{*params.RedirectURI}); err != nil {
			return ErrAccessDenied.WithError(err)
		}

		u, err := req.RedirectURI.Parse()
		if err != nil {
			return api.ErrBadRequest.WithError(err)
		}

		api.Redirect(u)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}

// Name implements api.Route
func (PasswordUpdateRoute) Name() string {
	return "password-update"
}

// Methods implements api.Route
func (PasswordUpdateRoute) Methods() []string {
	return []string{http.MethodPut}
}

// Path implements api.Route
func (PasswordUpdateRoute) Path() string {
	return "/password"
}

// RequireAuth implements the api.AuthorizedRoute
func (PasswordUpdateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (PasswordUpdateRoute) Scopes() ScopeList {
	return BuildScope(ScopePassword)
}

func (n passwordNotification) Type() NotificationType {
	return NotificationTypePassword
}

func (n passwordNotification) Subject() string {
	return n.login
}

func (n passwordNotification) URI() *URI {
	return n.uri
}

func (n passwordNotification) PasswordType() PasswordType {
	return n.passwordType
}

func (n passwordNotification) Code() string {
	return n.code
}

func (n passwordNotification) Channels() []NotificationChannel {
	return n.notify
}

// IsLink returns true if its a link type
func (p PasswordType) IsLink() bool {
	return p == PasswordTypeLink || p == PasswordTypeReset
}

func (p PasswordType) String() string {
	return string(p)
}

func generatePasscode(max int) string {
	b := make([]byte, max)
	n, err := io.ReadAtLeast(rand.Reader, b, max)
	if n != max {
		panic(err)
	}
	for i := 0; i < len(b); i++ {
		b[i] = passcodeAlpha[int(b[i])%len(passcodeAlpha)]
	}
	return string(b)
}
