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
	"github.com/ModelRocket/hiro/pkg/types"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// RequestToken represents an oauth request used for several different flows
	// These tokens are generally single use and should not be exposed, other than their id
	RequestToken struct {
		ID                  types.ID
		Type                RequestTokenType
		CreatedAt           Time
		Audience            string
		ClientID            string
		Subject             string
		Passcode            *string
		Uses                int
		Scope               Scope
		ExpiresAt           Time
		CodeChallenge       PKCEChallenge
		CodeChallengeMethod PKCEChallengeMethod
		AppURI              URI
		RedirectURI         *URI
		State               *string
	}

	// RequestTokenType is the request token type
	RequestTokenType string
)

const (
	// RequestTokenTypeLogin is used for login or signup routes
	RequestTokenTypeLogin RequestTokenType = "login"

	// RequestTokenTypeSession is used for sessions
	RequestTokenTypeSession RequestTokenType = "session"

	// RequestTokenTypeVerify is verification, i.e. password resets
	RequestTokenTypeVerify RequestTokenType = "verify"

	// RequestTokenTypeInvite is verification, i.e. password resets
	RequestTokenTypeInvite RequestTokenType = "invite"

	// RequestTokenTypeAuthCode is used to request token
	RequestTokenTypeAuthCode RequestTokenType = "auth_code"

	// RequestTokenTypeRefreshToken is used to request refresh token
	RequestTokenTypeRefreshToken RequestTokenType = "refresh_token"
)

// Validate validates the Request
func (r RequestToken) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.Type, validation.Required, validation.In(
			RequestTokenTypeLogin,
			RequestTokenTypeSession,
			RequestTokenTypeInvite,
			RequestTokenTypeVerify,
			RequestTokenTypeAuthCode,
			RequestTokenTypeRefreshToken)),
		validation.Field(&r.Audience, validation.Required),
		validation.Field(&r.ClientID, validation.Required),
		validation.Field(&r.Subject, validation.NilOrNotEmpty),
		validation.Field(&r.CodeChallenge, validation.Required),
		validation.Field(&r.CodeChallengeMethod, validation.Required),
		validation.Field(&r.ExpiresAt, validation.Required),
		validation.Field(&r.AppURI, validation.Required, is.RequestURI),
		validation.Field(&r.RedirectURI, validation.Required, is.RequestURI),
		validation.Field(&r.Scope, validation.Required),
		validation.Field(&r.State, validation.NilOrNotEmpty),
	)
}
