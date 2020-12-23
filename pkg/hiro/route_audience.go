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

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/oauth"
)

type (
	// AudienceCountParams are the params for the audience count route
	AudienceCountParams struct{}

	// AudienceCountRoute is the audience count route definition
	AudienceCountRoute func(ctx context.Context, params *AudienceCountParams) api.Responder

	// AudienceListParams are the params for the audience count route
	AudienceListParams struct {
		Offset *uint64 `json:"offset,omitempty"`
		Limit  *uint64 `json:"limit"`
	}

	// AudienceListRoute is the audience count route definition
	AudienceListRoute func(ctx context.Context, params *AudienceListParams) api.Responder
)

// Name implements api.Route
func (AudienceCountParams) Name() string {
	return "audience:count"
}

// Methods implements api.Route
func (AudienceCountParams) Methods() []string {
	return []string{http.MethodHead}
}

// Path implements api.Route
func (AudienceCountParams) Path() string {
	return "/verify"
}

// RequireAuth implements the api.AuthorizedRoute
func (AudienceCountParams) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AudienceCountParams) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAudienceRead)
}
