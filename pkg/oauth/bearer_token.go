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

import "time"

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
		RefreshToken *string `json:"refresh_token,omitempty"`

		// The token type, always Bearer
		TokenType string `json:"token_type"`
	}
)

// NewBearer creates a bearer from the tokens
func NewBearer(secret TokenSecret, tokens ...Token) (*BearerToken, error) {
	bearer := &BearerToken{
		TokenType: "Bearer",
	}

	for _, t := range tokens {
		switch t.Use {
		case TokenUseAccess:
			if bearer.AccessToken != "" {
				continue
			}
			a, err := t.Sign(secret)
			if err != nil {
				return nil, err
			}
			bearer.AccessToken = a
			bearer.ExpiresIn = int64(t.ExpiresAt.Time().Sub(time.Now()).Seconds())

		case TokenUseIdentity:
			if bearer.IdentityToken != "" {
				continue
			}
			i, err := t.Sign(secret)
			if err != nil {
				return nil, err
			}
			bearer.IdentityToken = i
		}
	}

	return bearer, nil
}
