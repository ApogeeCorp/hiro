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
	"path"
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/oauth/openid"
	"github.com/ModelRocket/hiro/pkg/ptr"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// VerifyParams are the params for user verify
	VerifyParams struct {
		RedirectURI *URI    `json:"redirect_uri"`
		State       *string `json:"state,omitempty"`
	}

	// VerifySendParams are the params for the verification send method
	VerifySendParams struct {
		Method NotificationChannel `json:"method"`
	}

	verifyNotification struct {
		sub     string
		uri     URI
		channel NotificationChannel
	}

	// VerificationNotification is a user verification notification
	VerificationNotification interface {
		Notification
	}
)

// Validate validates the params
func (p VerifyParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.RedirectURI, validation.NilOrNotEmpty, is.RequestURI))
}

// Validate validates the params
func (p VerifySendParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Method, validation.Required))
}

func verify(ctx context.Context, params *VerifyParams) api.Responder {
	var token Token

	ctrl := api.Context(ctx).(Controller)

	api.RequirePrincipal(ctx, &token, api.PrincipalTypeUser)

	if token.Use != TokenUseVerify {
		return api.ErrForbidden
	}

	// we revoke verify tokens once they have been used
	ctrl.TokenRevoke(ctx, token.ID)

	if params.RedirectURI != nil {
		aud, err := ctrl.AudienceGet(ctx, token.Audience)
		if err != nil {
			return api.ErrForbidden.WithError(err)
		}

		client, err := ctrl.ClientGet(ctx, token.ClientID)
		if err != nil {
			return api.ErrForbidden.WithError(err)
		}

		if err := client.Authorize(ctx, aud, GrantTypeNone, []URI{*params.RedirectURI}); err != nil {
			return api.ErrForbidden.WithError(err)
		}
	}

	var profile openid.Profile

	if token.Scope.Contains(ScopeEmailVerify) {
		profile.EmailClaim = new(openid.EmailClaim)
		profile.EmailVerified = ptr.True
	}

	if token.Scope.Contains(ScopePhoneVerify) {
		profile.PhoneClaim = new(openid.PhoneClaim)
		profile.PhoneNumberVerified = ptr.True
	}

	err := ctrl.UserUpdate(ctx, *token.Subject, &profile)

	if params.RedirectURI == nil {
		if err != nil {
			return api.Error(err)
		}
		return api.NewResponse().WithStatus(http.StatusNoContent)
	}

	u, err := params.RedirectURI.Parse()
	if err != nil {
		return api.ErrBadRequest.WithError(err)
	}

	if params.State != nil {
		q := u.Query()
		q.Set("state", *params.State)
		u.RawQuery = q.Encode()
	}

	return api.Redirect(u, err)
}

func verifySend(ctx context.Context, params *VerifySendParams) api.Responder {
	var token Token
	scope := Scope{ScopeOpenID, ScopeProfile}

	ctrl := api.Context(ctx).(Controller)

	api.RequirePrincipal(ctx, &token, api.PrincipalTypeUser)

	r, _ := api.Request(ctx)

	switch params.Method {
	case NotificationChannelEmail:
		scope = append(scope, ScopeEmailVerify)
	case NotificationChannelPhone:
		scope = append(scope, ScopePhoneVerify)
	default:
		return api.ErrBadRequest.WithDetail("unsupported notification channel")
	}

	issuer := URI(
		fmt.Sprintf("https://%s%s",
			r.Host,
			path.Clean(path.Join(path.Dir(r.URL.Path), "openid", token.Audience))),
	)

	// revoke any existing verify tokens
	ctrl.TokenRevokeAll(ctx, *token.Subject, TokenUseVerify)

	v, err := ctrl.TokenCreate(ctx, Token{
		Issuer:    &issuer,
		Subject:   token.Subject,
		Audience:  token.Audience,
		ClientID:  token.ClientID,
		Use:       TokenUseVerify,
		Revokable: true,
		ExpiresAt: Time(time.Now().Add(time.Hour * 24)).Ptr(),
		Scope:     scope,
	})
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	link, err := URI(
		fmt.Sprintf("https://%s%s",
			r.Host,
			path.Clean(r.URL.Path))).Parse()
	if err != nil {
		return api.ErrServerError.WithError(err)
	}
	q := link.Query()
	q.Set("access_token", v.ID.String())
	link.RawQuery = q.Encode()

	if err := ctrl.UserNotify(ctx, &verifyNotification{
		sub:     *token.Subject,
		channel: params.Method,
		uri:     URI(link.String()),
	}); err != nil {
		return api.ErrServerError.WithError(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}

func (n verifyNotification) Type() NotificationType {
	return NotificationTypeVerify
}

func (n verifyNotification) Subject() string {
	return n.sub
}

func (n verifyNotification) URI() *URI {
	return &n.uri
}

func (n verifyNotification) Channels() []NotificationChannel {
	return []NotificationChannel{NotificationChannel(n.channel)}
}
