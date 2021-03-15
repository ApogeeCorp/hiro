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
	// ErrAccessDenied is returned when authentication has failed
	ErrAccessDenied = api.ErrUnauthorized

	// ErrClientNotFound is returned when the controller could not find the client
	ErrClientNotFound = api.ErrNotFound.WithMessage("client not found")

	// ErrAudienceNotFound is returned when the store could not find the audience
	ErrAudienceNotFound = api.ErrNotFound.WithMessage("audience not found")

	// ErrUserNotFound is returned when the store could not find the user
	ErrUserNotFound = api.ErrNotFound.WithMessage("user not found")

	// ErrSessionNotFound is returned when the session was not found by the controller
	ErrSessionNotFound = api.ErrNotFound.WithMessage("session not found")

	// ErrUnsupportedAlogrithm is returned when the Authorizer gets a bad token
	ErrUnsupportedAlogrithm = api.ErrBadRequest.WithDetail("unsupported signing algorithm")

	// ErrInvalidToken is returned when the token is not valid
	ErrInvalidToken = ErrAccessDenied.WithDetail("invalid token")

	// ErrKeyNotFound is returned when the authorizer can not find a good key
	ErrKeyNotFound = ErrAccessDenied.WithDetail("suitable verification key not found")

	// ErrRevokedToken is returned when the token is revoked
	ErrRevokedToken = ErrAccessDenied.WithDetail("revoked token")

	// ErrExpiredToken is returned when the token is expired
	ErrExpiredToken = ErrAccessDenied.WithDetail("expired token")

	// ErrPasswordLen is returned when a password does not meet length requirements
	ErrPasswordLen = api.ErrBadRequest.WithDetail("invalid password length")

	// ErrPasswordComplexity is returned if the password does not meet complexity requirements
	ErrPasswordComplexity = api.ErrBadRequest.WithDetail("password does not meet complexity requirements")

	// ErrPasswordResuse is returned if password does not meet the reuse constraints
	ErrPasswordResuse = api.ErrBadRequest.WithDetail("password has been used before")

	// ErrPasswordExpired is returned when the password has expired
	ErrPasswordExpired = api.ErrBadRequest.WithDetail("password has expired")

	// ErrInvalidInviteCode is returned when an invitation code is bad
	ErrInvalidInviteCode = api.ErrBadRequest.WithDetail("invite code is invalid")
)

// NewErrTooManyLoginAttempts creates a new too many login attempts error
func NewErrTooManyLoginAttempts(attempts int) *ErrTooManyLoginAttempts {
	return &ErrTooManyLoginAttempts{
		ErrorResponse: ErrAccessDenied.WithDetail("too many login attempts"),
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
