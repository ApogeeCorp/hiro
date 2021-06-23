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
	"github.com/ModelRocket/hiro/pkg/api"
)

type (
	// ErrTooManyLoginAttempts is returned when too many login attempts have been exceeded
	ErrTooManyLoginAttempts struct {
		api.ErrorResponse
		Attempts int
	}
)

var (
	// ErrUnauthorized is returned when authentication has failed
	ErrUnauthorized = api.ErrUnauthorized.WithCode("access_denied")

	// ErrForbidden is returned when authorization has failed
	ErrForbidden = api.ErrForbidden.WithCode("access_denied")

	// ErrClientNotFound is returned when the controller could not find the client
	ErrClientNotFound = api.ErrNotFound.WithMessage("client not found")

	// ErrAudienceNotFound is returned when the store could not find the audience
	ErrAudienceNotFound = api.ErrNotFound.WithMessage("audience not found")

	// ErrUserNotFound is returned when the store could not find the user
	ErrUserNotFound = api.ErrNotFound.WithMessage("user not found")

	// ErrSessionNotFound is returned when the session was not found by the controller
	ErrSessionNotFound = api.ErrNotFound.WithMessage("session not found")

	// ErrUnsupportedAlogrithm is returned when the Authorizer gets a bad token
	ErrUnsupportedAlogrithm = api.ErrBadRequest.WithMessage("unsupported signing algorithm")

	// ErrInvalidToken is returned when the token is not valid
	ErrInvalidToken = api.ErrBadRequest.WithCode("invalid_token")

	// ErrInvalidGrant is returned when the grant is not valid for the client
	ErrInvalidGrant = api.ErrBadRequest.WithCode("invalid_grant")

	// ErrInvalidClient is returned when the client is not valid
	ErrInvalidClient = ErrUnauthorized.WithCode("invalid_client")

	// ErrKeyNotFound is returned when the authorizer can not find a good key
	ErrKeyNotFound = ErrUnauthorized.WithMessage("suitable verification key not found")

	// ErrRevokedToken is returned when the token is revoked
	ErrRevokedToken = ErrUnauthorized.WithCode("revoked_token")

	// ErrExpiredToken is returned when the token is expired
	ErrExpiredToken = ErrUnauthorized.WithCode("expired_token")

	// ErrPasswordLen is returned when a password does not meet length requirements
	ErrPasswordLen = api.ErrBadRequest.WithMessage("invalid password length")

	// ErrPasswordComplexity is returned if the password does not meet complexity requirements
	ErrPasswordComplexity = api.ErrBadRequest.WithMessage("password does not meet complexity requirements")

	// ErrPasswordResuse is returned if password does not meet the reuse constraints
	ErrPasswordResuse = api.ErrBadRequest.WithMessage("password has been used before")

	// ErrPasswordExpired is returned when the password has expired
	ErrPasswordExpired = api.ErrBadRequest.WithMessage("password has expired")

	// ErrInvalidInviteCode is returned when an invitation code is bad
	ErrInvalidInviteCode = api.ErrBadRequest.WithMessage("invite code is invalid")

	// ErrUnauthorizedClient is returned when a client is not allow access to a method
	ErrUnauthorizedClient = api.ErrUnauthorized.WithCode("unauthorized_client")

	// ErrInvalidScope is returned when a client requests an invalid scope
	ErrInvalidScope = api.ErrBadRequest.WithCode("invalid_code")

	// ErrInvalidRequest is returned when a client request is invalid
	ErrInvalidRequest = api.ErrBadRequest.WithCode("invalid_request")
)

// NewErrTooManyLoginAttempts creates a new too many login attempts error
func NewErrTooManyLoginAttempts(attempts int) *ErrTooManyLoginAttempts {
	return &ErrTooManyLoginAttempts{
		ErrorResponse: ErrUnauthorized.WithDetail("too many login attempts"),
		Attempts:      attempts,
	}
}

// WithError implements some of api.ErrorResponse interface
func (e ErrTooManyLoginAttempts) WithError(err error) api.ErrorResponse {
	return ErrTooManyLoginAttempts{
		ErrorResponse: e.ErrorResponse.WithError(err),
		Attempts:      e.Attempts,
	}
}
