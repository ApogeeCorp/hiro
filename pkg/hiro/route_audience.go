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
	"github.com/spf13/cast"
)

type (
	// AudienceCreateRoute is the audience create route definition
	AudienceCreateRoute func(ctx context.Context, params *AudienceCreateInput) api.Responder

	// AudienceGetRoute is the audience create route definition
	AudienceGetRoute func(ctx context.Context, params *AudienceGetInput) api.Responder

	// AudienceCountRoute is the audience count route definition
	AudienceCountRoute func(ctx context.Context, params *AudienceListInput) api.Responder

	// AudienceListRoute is the audience count route definition
	AudienceListRoute func(ctx context.Context, params *AudienceListInput) api.Responder

	// AudienceUpdateRoute is the audience create route definition
	AudienceUpdateRoute func(ctx context.Context, params *AudienceUpdateInput) api.Responder

	// AudienceDeleteRoute is the audience create route definition
	AudienceDeleteRoute func(ctx context.Context, params *AudienceDeleteInput) api.Responder
)

func audienceCreate(ctx context.Context, params *AudienceCreateInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	aud, err := ctrl.AudienceCreate(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(aud).WithStatus(http.StatusCreated)
}

func audienceGet(ctx context.Context, params *AudienceGetInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	aud, err := ctrl.AudienceGet(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(aud)
}

func audienceCount(ctx context.Context, params *AudienceListInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)
	var count uint64

	params.Offset = nil
	params.Limit = nil
	params.Count = &count

	_, err := ctrl.AudienceList(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithHeader("X-Query-Count", cast.ToString(params.Count))
}

func audienceList(ctx context.Context, params *AudienceListInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	auds, err := ctrl.AudienceList(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(auds).WithHeader("X-Query-Count", cast.ToString(len(auds)))
}

func audienceUpdate(ctx context.Context, params *AudienceUpdateInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	aud, err := ctrl.AudienceUpdate(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(aud)
}

func audienceDelete(ctx context.Context, params *AudienceDeleteInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	if err := ctrl.AudienceDelete(ctx, *params); err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}

// Name implements api.Route
func (AudienceCreateRoute) Name() string {
	return "audience:create"
}

// Methods implements api.Route
func (AudienceCreateRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (AudienceCreateRoute) Path() string {
	return "/audiences"
}

// RequireAuth implements the api.AuthorizedRoute
func (AudienceCreateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AudienceCreateRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAudienceWrite)
}

// Name implements api.Route
func (AudienceGetRoute) Name() string {
	return "audience:get"
}

// Methods implements api.Route
func (AudienceGetRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (AudienceGetRoute) Path() string {
	return "/audiences"
}

// RequireAuth implements the api.AuthorizedRoute
func (AudienceGetRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AudienceGetRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAudienceRead)
}

// Name implements api.Route
func (AudienceCountRoute) Name() string {
	return "audience:count"
}

// Methods implements api.Route
func (AudienceCountRoute) Methods() []string {
	return []string{http.MethodHead}
}

// Path implements api.Route
func (AudienceCountRoute) Path() string {
	return "/audiences"
}

// RequireAuth implements the api.AuthorizedRoute
func (AudienceCountRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AudienceCountRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAudienceRead)
}

// Name implements api.Route
func (AudienceListRoute) Name() string {
	return "audience:list"
}

// Methods implements api.Route
func (AudienceListRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (AudienceListRoute) Path() string {
	return "/audiences"
}

// RequireAuth implements the api.AuthorizedRoute
func (AudienceListRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AudienceListRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAudienceRead)
}

// Name implements api.Route
func (AudienceUpdateRoute) Name() string {
	return "audience:update"
}

// Methods implements api.Route
func (AudienceUpdateRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (AudienceUpdateRoute) Path() string {
	return "/audiences/{audience_id}"
}

// RequireAuth implements the api.AuthorizedRoute
func (AudienceUpdateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AudienceUpdateRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAudienceWrite)
}

// Name implements api.Route
func (AudienceDeleteRoute) Name() string {
	return "audience:delete"
}

// Methods implements api.Route
func (AudienceDeleteRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (AudienceDeleteRoute) Path() string {
	return "/audiences/{audience_id}"
}

// RequireAuth implements the api.AuthorizedRoute
func (AudienceDeleteRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AudienceDeleteRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAudienceWrite)
}
