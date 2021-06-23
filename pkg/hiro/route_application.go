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
	// ApplicationCreateRoute is the application create route definition
	ApplicationCreateRoute func(ctx context.Context, params *ApplicationCreateInput) api.Responder

	// ApplicationGetRoute is the application create route definition
	ApplicationGetRoute func(ctx context.Context, params *ApplicationGetInput) api.Responder

	// ApplicationCountRoute is the application count route definition
	ApplicationCountRoute func(ctx context.Context, params *ApplicationListInput) api.Responder

	// ApplicationListRoute is the application count route definition
	ApplicationListRoute func(ctx context.Context, params *ApplicationListInput) api.Responder

	// ApplicationUpdateRoute is the application create route definition
	ApplicationUpdateRoute func(ctx context.Context, params *ApplicationUpdateInput) api.Responder

	// ApplicationDeleteRoute is the application create route definition
	ApplicationDeleteRoute func(ctx context.Context, params *ApplicationDeleteInput) api.Responder
)

// Name implements api.Route
func (ApplicationCreateRoute) Name() string {
	return "application:create"
}

// Methods implements api.Route
func (ApplicationCreateRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (ApplicationCreateRoute) Path() string {
	return "/applications"
}

// RequireAuth implements the api.AuthorizedRoute
func (ApplicationCreateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (ApplicationCreateRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeApplicationWrite)
}

func applicationCreate(ctx context.Context, params *ApplicationCreateInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	inst, err := ctrl.ApplicationCreate(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(inst).WithStatus(http.StatusCreated)
}

// Name implements api.Route
func (ApplicationGetRoute) Name() string {
	return "application:get"
}

// Methods implements api.Route
func (ApplicationGetRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (ApplicationGetRoute) Path() string {
	return "/applications"
}

// RequireAuth implements the api.AuthorizedRoute
func (ApplicationGetRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (ApplicationGetRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeApplicationRead)
}

func applicationGet(ctx context.Context, params *ApplicationGetInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	inst, err := ctrl.ApplicationGet(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(inst)
}

// Name implements api.Route
func (ApplicationCountRoute) Name() string {
	return "application:count"
}

// Methods implements api.Route
func (ApplicationCountRoute) Methods() []string {
	return []string{http.MethodHead}
}

// Path implements api.Route
func (ApplicationCountRoute) Path() string {
	return "/applications"
}

// RequireAuth implements the api.AuthorizedRoute
func (ApplicationCountRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (ApplicationCountRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeApplicationRead)
}

func applicationCount(ctx context.Context, params *ApplicationListInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)
	var count uint64

	params.Offset = nil
	params.Limit = nil
	params.Count = &count

	_, err := ctrl.ApplicationList(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithHeader("X-Query-Count", cast.ToString(params.Count))
}

// Name implements api.Route
func (ApplicationListRoute) Name() string {
	return "application:list"
}

// Methods implements api.Route
func (ApplicationListRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (ApplicationListRoute) Path() string {
	return "/applications"
}

// RequireAuth implements the api.AuthorizedRoute
func (ApplicationListRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (ApplicationListRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeApplicationRead)
}

func applicationList(ctx context.Context, params *ApplicationListInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	auds, err := ctrl.ApplicationList(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(auds).WithHeader("X-Query-Count", cast.ToString(len(auds)))
}

// Name implements api.Route
func (ApplicationUpdateRoute) Name() string {
	return "application:update"
}

// Methods implements api.Route
func (ApplicationUpdateRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (ApplicationUpdateRoute) Path() string {
	return "/applications/{application_id}"
}

// RequireAuth implements the api.AuthorizedRoute
func (ApplicationUpdateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (ApplicationUpdateRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeApplicationWrite)
}

func applicationUpdate(ctx context.Context, params *ApplicationUpdateInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	inst, err := ctrl.ApplicationUpdate(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(inst)
}

// Name implements api.Route
func (ApplicationDeleteRoute) Name() string {
	return "application:delete"
}

// Methods implements api.Route
func (ApplicationDeleteRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (ApplicationDeleteRoute) Path() string {
	return "/applications/{application_id}"
}

// RequireAuth implements the api.AuthorizedRoute
func (ApplicationDeleteRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (ApplicationDeleteRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeApplicationWrite)
}

func applicationDelete(ctx context.Context, params *ApplicationDeleteInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	if err := ctrl.ApplicationDelete(ctx, *params); err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}
