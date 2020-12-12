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

		// RequestCreate creates a new authentication request token using the controller
		RequestCreate(ctx context.Context, req Request) (string, error)

		// RequestGet looks up a request by id from the controller
		RequestGet(ctx context.Context, id string) (*Request, error)

		// TokenCreate creates a new token in the controller
		TokenCreate(ctx context.Context, token *AccessToken) error

		// TokenFinalize finalizes the token and returns the signed and encoded token
		TokenFinalize(ctx context.Context, token *AccessToken) (string, error)
	}
)
