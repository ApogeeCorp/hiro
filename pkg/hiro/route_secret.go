/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://githuh.com/ModelRocket/hiro
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

package hiro

import (
	"context"
	"net/http"

	"github.com/ModelRocket/sparks/pkg/oauth"
	"github.com/ModelRocket/sparks/pkg/api"
)

type (
	// SecretCreateRoute is the secret create route definition
	SecretCreateRoute func(ctx context.Context, params *SecretCreateInput) api.Responder

	// SecretDeleteRoute is the secret create route definition
	SecretDeleteRoute func(ctx context.Context, params *SecretDeleteInput) api.Responder
)

func secretCreate(ctx context.Context, params *SecretCreateInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	aud, err := ctrl.SecretCreate(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(aud).WithStatus(http.StatusCreated)
}

func secretDelete(ctx context.Context, params *SecretDeleteInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	if err := ctrl.SecretDelete(ctx, *params); err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}

// Name implements api.Route
func (SecretCreateRoute) Name() string {
	return "secret:create"
}

// Methods implements api.Route
func (SecretCreateRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (SecretCreateRoute) Path() string {
	return "/audiences/{audience_id}/secrets"
}

// RequireAuth implements the api.AuthorizedRoute
func (SecretCreateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (SecretCreateRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAudienceWrite)
}

// Name implements api.Route
func (SecretDeleteRoute) Name() string {
	return "secret:delete"
}

// Methods implements api.Route
func (SecretDeleteRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (SecretDeleteRoute) Path() string {
	return "/audiences/{audience_id}/secrets/{secret_id}"
}

// RequireAuth implements the api.AuthorizedRoute
func (SecretDeleteRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (SecretDeleteRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAudienceWrite)
}
