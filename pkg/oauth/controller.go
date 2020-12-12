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

import "context"

type (
	// Controller defines an oauth server controller interface
	Controller interface {
		// ClientGet gets the client from the controller
		ClientGet(ctx context.Context, id string) (Client, error)

		// RequestTokenCreate creates a new authentication request token using the controller
		RequestTokenCreate(ctx context.Context, req RequestToken) (string, error)

		// RequestTokenGet looks up a request by id from the controller
		RequestTokenGet(ctx context.Context, id string) (RequestToken, error)

		// UserGet gets a user object by id
		UserGet(ctx context.Context, id string) (User, error)

		// UserAuthenticate authenticates a user and returns a principal object
		UserAuthenticate(ctx context.Context, login, password string) (User, error)

		// TokenCreate creates a new access token
		TokenCreate(ctx context.Context, token AccessToken) error

		// TokenFinalize finalizes the token and returns the signed and encoded value
		TokenFinalize(ctx context.Context, token AccessToken) (string, error)
	}
)
