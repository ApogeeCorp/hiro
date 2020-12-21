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
