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
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// RequestToken represents an oauth request used for several different flows
	// These tokens are generally single use and should not be exposed, other than their id
	RequestToken struct {
		ID                  ID
		Type                RequestTokenType
		CreatedAt           Time
		Audience            string
		ClientID            string
		Subject             *string
		Passcode            *string
		Uses                int
		Scope               Scope
		ExpiresAt           Time
		CodeChallenge       PKCEChallenge
		CodeChallengeMethod PKCEChallengeMethod
		AppURI              *URI
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
