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

type (

	// BearerToken BearerTokens are returned by the `/token` method. These token always include
	// an `access_token` which can be used to access api methods from a related service.
	// These are the only objects managed by the api itself. The integration is expected
	// to implement the `oauth.Controller` interface.
	BearerToken struct {
		// The token to be used for authorization
		AccessToken string `json:"access_token"`

		// The time from `now` that the token expires
		ExpiresIn int64 `json:"expires_in"`

		// The idenity token contains claims about the users identity. This token is
		// returned if the `openid` scope was granted.
		// If the `profile` scope was granted, this will contain the user profile.
		// These scopes are outside of the context of this library, it is up to the
		// provider to maintain these scopes.
		IdentityToken string `json:"id_token,omitempty"`

		// The refresh token maybe used to generate a new access token so client
		// and user credentials do not have to traverse the wire again.
		// The is provided if the `offline_access` scope is request.
		// This scopes are outside of the context of this library, it is up to the
		RefreshToken string `json:"refresh_token,omitempty"`

		// The token type, always Bearer
		TokenType string `json:"token_type"`
	}
)
