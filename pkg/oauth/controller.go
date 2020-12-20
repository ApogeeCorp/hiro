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

	"github.com/ModelRocket/hiro/pkg/oauth/openid"
	"github.com/ModelRocket/hiro/pkg/types"
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

		// TokenCreate creates a new token and allows the controller to add custom claims
		TokenCreate(ctx context.Context, token Token) (Token, error)

		// TokenGet gets a token by id
		TokenGet(ctx context.Context, id string, use ...TokenUse) (Token, error)

		// TokenRevoke revokes a token by id
		TokenRevoke(ctx context.Context, id types.ID) error

		// TokenRevokeAll will remove all tokens for a subject
		TokenRevokeAll(ctx context.Context, sub string, uses ...TokenUse) error

		// TokenCleanup should remove any expired or revoked tokens from the store
		TokenCleanup(ctx context.Context) error
	}
)
