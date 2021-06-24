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
	"time"

	"github.com/ModelRocket/hiro/pkg/oauth/openid"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// AudienceGetInput is the input for AudienceGet
	AudienceGetInput struct {
		Audience string `json:"audience"`
	}

	// ClientGetInput is the input for ClientGet
	ClientGetInput struct {
		Audience     string  `json:"audience"`
		ClientID     string  `json:"client_id"`
		ClientSecret *string `json:"client_secret,omitempty"`
	}

	// RequestTokenGetInput is the input for RequestTokenGet
	RequestTokenGetInput struct {
		TokenID   string            `json:"token_id"`
		TokenType *RequestTokenType `json:"token_type"`
	}

	// RequestTokenDeleteInput is the input for RequestTokenDelete
	RequestTokenDeleteInput struct {
		TokenID string `json:"token_id"`
	}

	// UserCreateInput is the input to UserCreate
	UserCreateInput struct {
		Audience string          `json:"audience"`
		Login    string          `json:"login"`
		Password *string         `json:"password,omitempty"`
		Profile  *openid.Profile `json:"profile,omitempty"`
		Invite   *RequestToken   `json:"invite,omitempty"`
	}

	// UserGetInput is the input for UserGet
	UserGetInput struct {
		Audience string  `json:"audience"`
		Login    *string `json:"login,omitempty"`
		Subject  *string `json:"subject,omitempty"`
		Password *string `json:"password,omitempty"`
	}

	// UserUpdateInput is the input to UserUpdate
	UserUpdateInput struct {
		Audience  string          `json:"audience"`
		Login     *string         `json:"login,omitempty"`
		Subject   *string         `json:"subject,omitempty"`
		Password  *string         `json:"password,omitempty"`
		Profile   *openid.Profile `json:"profile,omitempty"`
		Lockout   *bool           `json:"lockout,omitempty"`
		LockUntil *time.Time      `json:"lock_until,omitempty"`
	}

	// TokenGetInput is the input to TokenGet
	TokenGetInput struct {
		TokenID  string    `json:"token_id"`
		TokenUse *TokenUse `json:"token_use,omitempty"`
	}

	// TokenRevokeInput is the input to TokenRevoke
	TokenRevokeInput struct {
		TokenID  *string   `json:"token_id,omitempty"`
		Subject  *string   `json:"subject,omitempty"`
		TokenUse *TokenUse `json:"token_use,omitempty"`
	}

	// Controller defines an oauth controller interface
	Controller interface {
		// AudienceGet returns an audience
		AudienceGet(context.Context, AudienceGetInput) (Audience, error)

		// ClientGet returns a client principal object
		ClientGet(context.Context, ClientGetInput) (Client, error)

		// RequestTokenCreate creates a new authentication request token using the controller
		RequestTokenCreate(context.Context, RequestToken) (string, error)

		// RequestTokenGet looks up a request from the controller
		RequestTokenGet(context.Context, RequestTokenGetInput) (RequestToken, error)

		// RequestTokenDelete deletes a request token
		RequestTokenDelete(context.Context, RequestTokenDeleteInput) error

		// UserCreate creates a user with the audience
		UserCreate(context.Context, UserCreateInput) (User, error)

		// UserGet gets a user principal object
		UserGet(context.Context, UserGetInput) (User, error)

		// UserUpdate updates a user
		UserUpdate(context.Context, UserUpdateInput) (User, error)

		// UserNotify should create an email or sms with the verification link or code for the user
		UserNotify(context.Context, Notification) error

		// TokenCreate creates a new token and allows the controller to add custom claims
		TokenCreate(context.Context, Token) (Token, error)

		// TokenGet gets a token
		TokenGet(context.Context, TokenGetInput) (Token, error)

		// TokenRevoke revokes a token
		TokenRevoke(context.Context, TokenRevokeInput) error

		// TokenCleanup should cleanup all expired and revoked tokens from the stores
		TokenCleanup(ctx context.Context) error
	}
)

// Validate implements the validation.Validatable interface
func (i AudienceGetInput) Validate() error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.Audience, validation.Required),
	)
}

// Validate implements the validation.Validatable interface
func (i ClientGetInput) Validate() error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.Audience, validation.Required),
		validation.Field(&i.ClientID, validation.Required),
		validation.Field(&i.ClientSecret, validation.NilOrNotEmpty),
	)
}

// Validate implements the validation.Validatable interface
func (i RequestTokenGetInput) Validate() error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.TokenID, validation.Required),
		validation.Field(&i.TokenType, validation.NilOrNotEmpty),
	)
}

// Validate implements the validation.Validatable interface
func (i RequestTokenDeleteInput) Validate() error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.TokenID, validation.Required),
	)
}

// Validate implements the validation.Validatable interface
func (i UserCreateInput) Validate() error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.Audience, validation.Required),
		validation.Field(&i.Login, validation.Required),
		validation.Field(&i.Password, validation.NilOrNotEmpty),
		validation.Field(&i.Profile, validation.NilOrNotEmpty),
		validation.Field(&i.Invite, validation.NilOrNotEmpty),
	)
}

// Validate implements the validation.Validatable interface
func (i UserGetInput) Validate() error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.Audience, validation.Required),
		validation.Field(&i.Login, validation.When(i.Subject == nil, validation.Required)),
		validation.Field(&i.Subject, validation.When(i.Login == nil, validation.Required)),
		validation.Field(&i.Password, validation.NilOrNotEmpty),
	)
}

// Validate implements the validation.Validatable interface
func (i UserUpdateInput) Validate() error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.Audience, validation.Required),
		validation.Field(&i.Login, validation.When(i.Subject == nil, validation.Required)),
		validation.Field(&i.Subject, validation.When(i.Login == nil, validation.Required)),
		validation.Field(&i.Password, validation.NilOrNotEmpty),
		validation.Field(&i.Profile, validation.NilOrNotEmpty),
	)
}

// Validate implements the validation.Validatable interface
func (i TokenGetInput) Validate() error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.TokenID, validation.Required),
		validation.Field(&i.TokenUse, validation.NilOrNotEmpty),
	)
}

// Validate implements the validation.Validatable interface
func (i TokenRevokeInput) Validate() error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.TokenID, validation.When(i.Subject == nil, validation.Required)),
		validation.Field(&i.Subject, validation.When(i.TokenID == nil, validation.Required)),
		validation.Field(&i.TokenUse, validation.NilOrNotEmpty),
	)
}
