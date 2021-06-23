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
	// AssetCreateRoute is the asset create route definition
	AssetCreateRoute func(ctx context.Context, params *AssetCreateInput) api.Responder

	// AssetGetRoute is the asset create route definition
	AssetGetRoute func(ctx context.Context, params *AssetGetInput) api.Responder

	// AssetCountRoute is the asset count route definition
	AssetCountRoute func(ctx context.Context, params *AssetListInput) api.Responder

	// AssetListRoute is the asset count route definition
	AssetListRoute func(ctx context.Context, params *AssetListInput) api.Responder

	// AssetUpdateRoute is the asset create route definition
	AssetUpdateRoute func(ctx context.Context, params *AssetUpdateInput) api.Responder

	// AssetDeleteRoute is the asset create route definition
	AssetDeleteRoute func(ctx context.Context, params *AssetDeleteInput) api.Responder
)

// Name implements api.Route
func (AssetCreateRoute) Name() string {
	return "asset:create"
}

// Methods implements api.Route
func (AssetCreateRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (AssetCreateRoute) Path() string {
	return "/assets"
}

// RequireAuth implements the api.AuthorizedRoute
func (AssetCreateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AssetCreateRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAssetWrite)
}

func assetCreate(ctx context.Context, params *AssetCreateInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	inst, err := ctrl.AssetCreate(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(inst).WithStatus(http.StatusCreated)
}

// Name implements api.Route
func (AssetGetRoute) Name() string {
	return "asset:get"
}

// Methods implements api.Route
func (AssetGetRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (AssetGetRoute) Path() string {
	return "/assets"
}

// RequireAuth implements the api.AuthorizedRoute
func (AssetGetRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AssetGetRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAssetRead)
}

func assetGet(ctx context.Context, params *AssetGetInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	inst, err := ctrl.AssetGet(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(inst)
}

// Name implements api.Route
func (AssetCountRoute) Name() string {
	return "asset:count"
}

// Methods implements api.Route
func (AssetCountRoute) Methods() []string {
	return []string{http.MethodHead}
}

// Path implements api.Route
func (AssetCountRoute) Path() string {
	return "/assets"
}

// RequireAuth implements the api.AuthorizedRoute
func (AssetCountRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AssetCountRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAssetRead)
}

func assetCount(ctx context.Context, params *AssetListInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)
	var count uint64

	params.Offset = nil
	params.Limit = nil
	params.Count = &count

	_, err := ctrl.AssetList(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithHeader("X-Query-Count", cast.ToString(params.Count))
}

// Name implements api.Route
func (AssetListRoute) Name() string {
	return "asset:list"
}

// Methods implements api.Route
func (AssetListRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (AssetListRoute) Path() string {
	return "/assets"
}

// RequireAuth implements the api.AuthorizedRoute
func (AssetListRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AssetListRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAssetRead)
}

func assetList(ctx context.Context, params *AssetListInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	auds, err := ctrl.AssetList(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(auds).WithHeader("X-Query-Count", cast.ToString(len(auds)))
}

// Name implements api.Route
func (AssetUpdateRoute) Name() string {
	return "asset:update"
}

// Methods implements api.Route
func (AssetUpdateRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (AssetUpdateRoute) Path() string {
	return "/assets/{asset_id}"
}

// RequireAuth implements the api.AuthorizedRoute
func (AssetUpdateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AssetUpdateRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAssetWrite)
}

func assetUpdate(ctx context.Context, params *AssetUpdateInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	inst, err := ctrl.AssetUpdate(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(inst)
}

// Name implements api.Route
func (AssetDeleteRoute) Name() string {
	return "asset:delete"
}

// Methods implements api.Route
func (AssetDeleteRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (AssetDeleteRoute) Path() string {
	return "/assets/{asset_id}"
}

// RequireAuth implements the api.AuthorizedRoute
func (AssetDeleteRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (AssetDeleteRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeAssetWrite)
}

func assetDelete(ctx context.Context, params *AssetDeleteInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	if err := ctrl.AssetDelete(ctx, *params); err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}
