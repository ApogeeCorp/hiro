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
	"path"
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/ptr"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// PasswordGetInput is the input to the password get route
	PasswordGetInput struct {
		Login        string       `json:"login"`
		Type         PasswordType `json:"type"`
		RequestToken string       `json:"request_token"`
		CodeVerifier string       `json:"code_verifier"`
	}

	// PasswordType defines a password type
	PasswordType string

	// PasswordNotification is a password notification interface
	PasswordNotification interface {
		Notification
		PasswordType() PasswordType
		URI() *URI
		Code() *string
	}

	passwordNotification struct {
		login        string
		passwordType PasswordType
		uri          *URI
		code         *string
	}
)

const (
	// PasswordTypeLink is a magic password link
	PasswordTypeLink PasswordType = "link"

	// PasswordTypeCode is a one-time use password code
	PasswordTypeCode PasswordType = "code"

	// PasswordTypeReset sends both a link and code
	PasswordTypeReset PasswordType = "reset"
)

// Validate validates the PasswordType
func (p PasswordType) Validate() error {
	return validation.Validate(string(p), validation.In("link", "code", "reset"))
}

// Validate validates PasswordGetInput
func (p PasswordGetInput) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Login, validation.Required),
		validation.Field(&p.Type, validation.Required),
		validation.Field(&p.RequestToken, validation.Required),
		validation.Field(&p.CodeVerifier, validation.Required),
	)
}

func passwordCreate(ctx context.Context, params *PasswordGetInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	log := api.Log(ctx).WithField("operation", "login").WithField("login", params.Login)

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

	switch params.Type {
	case PasswordTypeLink:
		req.Scope = append(req.Scope, ScopeLogin)
		req.ExpiresAt = Time(time.Now().Add(time.Minute * 10))

		r, _ := api.Request(ctx)

		issuer := URI(
			fmt.Sprintf("https://%s%s",
				r.Host,
				path.Clean(path.Join(path.Dir(r.URL.Path), "openid", req.Audience))),
		)

		token, err := ctrl.TokenCreate(ctx, Token{
			Issuer:    &issuer,
			Subject:   ptr.String(user.Subject()),
			Audience:  req.Audience,
			ClientID:  req.ClientID,
			Use:       TokenUseAccess,
			ExpiresAt: Time(time.Now().Add(time.Hour * 1)).Ptr(),
			Revokable: true,
			AuthTime:  &req.CreatedAt,
			Scope:     append(req.Scope, ScopeLogin),
		})
		if err != nil {
			log.Error(err.Error())

			return api.Redirect(u, ErrAccessDenied.WithError(err))
		}

		link, err := URI(
			fmt.Sprintf("https://%s%s",
				r.Host,
				path.Clean(path.Join(path.Dir(r.URL.Path), "login")))).Parse()
		if err != nil {
			log.Error(err.Error())

			return api.Redirect(u, ErrAccessDenied.WithError(err))
		}
		q := link.Query()
		q.Set("access_token", token.ID.String())
		link.RawQuery = q.Encode()

		if err := ctrl.UserNotify(ctx, &passwordNotification{
			login:        params.Login,
			passwordType: params.Type,
			uri:          URI(link.String()).Ptr(),
		}); err != nil {
			log.Error(err.Error())

			return api.Redirect(u, ErrAccessDenied.WithError(err))
		}

		u, err = req.RedirectURI.Parse()
		if err != nil {
			return api.Redirect(u, ErrAccessDenied.WithError(err))
		}
		if req.State != nil {
			q := u.Query()
			q.Set("state", *req.State)
			u.RawQuery = q.Encode()
		}

		return api.Redirect(u)
	}

	return api.Redirect(u)
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

func (n passwordNotification) Code() *string {
	return n.code
}
