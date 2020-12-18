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

package api

import (
	"context"
	"net/http"
	"reflect"
)

type (
	// Authorizer performs an authorization and returns a context or error on failure
	Authorizer func(r *http.Request) (Principal, error)

	// Claims is a basic claims interface
	Claims interface {
		// Set sets a value in the claims
		Set(key string, value interface{})

		// Get gets a value in the claims
		Get(key string) interface{}

		// All should return all of the claims as a map
		All() map[string]interface{}
	}

	// Principal is an authorization principal
	Principal interface {
		// Type should return the principal type
		Type() PrincipalType

		// CredentialType should return the credential type, i.e. Basic or Bearer
		CredentialType() CredentialType

		// Credentials should return the raw principal credentials
		Credentials() string

		// Returns the principal's authorization claims
		AuthClaims() Claims
	}

	// PrincipalType defines a principal type
	PrincipalType string

	// CredentialType is the credential type
	CredentialType string
)

var (
	contextKeyAuth = contextKey("api:auth")

	prinType = reflect.TypeOf((*Principal)(nil)).Elem()
)

const (
	// PrincipalTypeUser should be returned if the principal is a user
	PrincipalTypeUser PrincipalType = "user"

	// PrincipalTypeApplication should be used if the principal is an application
	PrincipalTypeApplication PrincipalType = "application"

	// CredentialTypeBasic is http 401 Basic auth
	CredentialTypeBasic CredentialType = "Basic"

	// CredentialTypeBearer is HTTP Bearer token authentication
	CredentialTypeBearer CredentialType = "Bearer"

	// CredentialTypeAPIKey is used for other api key based authentications
	CredentialTypeAPIKey CredentialType = "ApiKey"
)

// Unauthorized fails auth and can used by routes in the authorizer chain as an
// explicit deny, this is useful when there are authorizers with optional components
func Unauthorized(r *http.Request) (interface{}, error) {
	return nil, ErrUnauthorized
}

// AuthPrincipal the first auth principal that matches the target
func AuthPrincipal(ctx context.Context, target interface{}) bool {
	prins, ok := ctx.Value(contextKeyAuth).([]Principal)

	if prins == nil || !ok {
		return false
	}

	val := reflect.ValueOf(target)
	typ := val.Type()
	if typ.Kind() != reflect.Ptr || val.IsNil() {
		panic(ErrAuthUnacceptable)
	}
	if p := typ.Elem(); p.Kind() != reflect.Interface && !p.Implements(prinType) {
		panic(ErrAuthUnacceptable)
	}

	targetType := typ.Elem()

	for _, prin := range prins {
		if reflect.TypeOf(prin).AssignableTo(targetType) {
			val.Elem().Set(reflect.ValueOf(prin))
			return true
		}
	}

	return false
}

// RequirePrincipal panics with api.ErrUnauthorized on fail
func RequirePrincipal(ctx context.Context, target interface{}, t ...PrincipalType) {
	if !AuthPrincipal(ctx, target) {
		panic(ErrUnauthorized)
	}

	if len(t) > 0 && target.(Principal).Type() != t[0] {
		panic(ErrUnauthorized)
	}
}
