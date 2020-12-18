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

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// Client is an oauth client interface
	Client interface {
		// ClientID returns the client id
		ClientID() string

		// Type returns the client type
		Type() ClientType

		// Authorize authorizes the client for the specified grants, uris, and scopes
		// Used for authorization_code flows
		Authorize(ctx context.Context, aud Audience, grant GrantType, uris []URI, scopes ...Scope) error
	}

	// ClientType is an oauth client type
	ClientType string
)

const (

	// ClientTypeWeb defines a web based client type
	// 	Web based clients are restricted from passing client_secret values
	// 	and using password grants
	ClientTypeWeb ClientType = "web"

	// ClientTypeNative defines a native application client type
	ClientTypeNative ClientType = "native"

	// ClientTypeMachine defines a machine to machine client type
	ClientTypeMachine ClientType = "machine"
)

// Validate handles validation for ClientType
func (c ClientType) Validate() error {
	return validation.Validate(string(c), validation.In("web", "native", "machine"))
}
