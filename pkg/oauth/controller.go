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
)

type (
	// Controller defines an oauth server controller interface
	Controller interface {
		// AudienceGet returns an audience by id or name
		AudienceGet(ctx context.Context, id string) (Audience, error)

		// ClientGet gets the client from the controller and optionally verfies the secret
		ClientGet(ctx context.Context, id string, secret ...string) (Client, error)

		// RequestTokenCreate creates a new authentication request token using the controller
		RequestTokenCreate(ctx context.Context, req RequestToken) (string, error)

		// RequestTokenGet looks up a request by id from the controller
		RequestTokenGet(ctx context.Context, id string, t ...RequestTokenType) (RequestToken, error)

		// RequestTokenDelete deletes a request token by id
		RequestTokenDelete(ctx context.Context, id string) error

		// UserGet gets a user object by subject identifier or login
		UserGet(ctx context.Context, sub string) (User, error)

		// UserAuthenticate authenticates a user and returns a principal object
		UserAuthenticate(ctx context.Context, login, password string) (User, error)

		// UserSetPassword sets the users password
		UserSetPassword(ctx context.Context, sub, password string) error

		// UserCreate creates a user using the request which can either be the authorize or an invite token
		UserCreate(ctx context.Context, login string, password *string, req RequestToken) (User, error)

		// UserUpdate updates a user's profile
		UserUpdate(ctx context.Context, sub string, profile *openid.Profile) error

		// UserNotify should create an email or sms with the verification link or code for the user
		UserNotify(ctx context.Context, note Notification) error

		// UserLockout should lock a user for the specified time or default
		UserLockout(ctx context.Context, sub string, until ...time.Time) (time.Time, error)

		// TokenCreate creates a new token and allows the controller to add custom claims
		TokenCreate(ctx context.Context, token Token) (Token, error)

		// TokenGet gets a token by id
		TokenGet(ctx context.Context, id string, use ...TokenUse) (Token, error)

		// TokenRevoke revokes a token by id
		TokenRevoke(ctx context.Context, id string) error

		// TokenRevokeAll will remove all tokens for a subject
		TokenRevokeAll(ctx context.Context, sub string, uses ...TokenUse) error

		// TokenCleanup should remove any expired or revoked tokens from the store
		TokenCleanup(ctx context.Context) error
	}

	// ControllerProxy returns an oauth controller
	ControllerProxy interface {
		OAuthController() Controller
	}
)
