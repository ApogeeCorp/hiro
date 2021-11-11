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
	// InstanceCreateRoute is the instance create route definition
	InstanceCreateRoute func(ctx context.Context, params *InstanceCreateParams) api.Responder

	// InstanceGetRoute is the instance create route definition
	InstanceGetRoute func(ctx context.Context, params *InstanceGetParams) api.Responder

	// InstanceCountRoute is the instance count route definition
	InstanceCountRoute func(ctx context.Context, params *InstanceListParams) api.Responder

	// InstanceListRoute is the instance count route definition
	InstanceListRoute func(ctx context.Context, params *InstanceListParams) api.Responder

	// InstanceUpdateRoute is the instance create route definition
	InstanceUpdateRoute func(ctx context.Context, params *InstanceUpdateParams) api.Responder

	// InstanceDeleteRoute is the instance create route definition
	InstanceDeleteRoute func(ctx context.Context, params *InstanceDeleteParams) api.Responder
)

func instanceCreate(ctx context.Context, params *InstanceCreateParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	inst, err := ctrl.InstanceCreate(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(inst).WithStatus(http.StatusCreated)
}

// Name implements api.Route
func (InstanceCreateRoute) Name() string {
	return "instance:create"
}

// Methods implements api.Route
func (InstanceCreateRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (InstanceCreateRoute) Path() string {
	return "/instances"
}

// RequireAuth implements the api.AuthorizedRoute
func (InstanceCreateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (InstanceCreateRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeInstanceWrite)
}

func instanceGet(ctx context.Context, params *InstanceGetParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	inst, err := ctrl.InstanceGet(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(inst)
}

// Name implements api.Route
func (InstanceGetRoute) Name() string {
	return "instance:get"
}

// Methods implements api.Route
func (InstanceGetRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (InstanceGetRoute) Path() string {
	return "/instances"
}

// RequireAuth implements the api.AuthorizedRoute
func (InstanceGetRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (InstanceGetRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeInstanceRead)
}

func instanceCount(ctx context.Context, params *InstanceListParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)
	var count uint64

	params.Offset = nil
	params.Limit = nil
	params.Count = &count

	_, err := ctrl.InstanceList(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithHeader("X-Query-Count", cast.ToString(params.Count))
}

// Name implements api.Route
func (InstanceCountRoute) Name() string {
	return "instance:count"
}

// Methods implements api.Route
func (InstanceCountRoute) Methods() []string {
	return []string{http.MethodHead}
}

// Path implements api.Route
func (InstanceCountRoute) Path() string {
	return "/instances"
}

// RequireAuth implements the api.AuthorizedRoute
func (InstanceCountRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (InstanceCountRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeInstanceRead)
}

func instanceList(ctx context.Context, params *InstanceListParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	auds, err := ctrl.InstanceList(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(auds).WithHeader("X-Query-Count", cast.ToString(len(auds)))
}

// Name implements api.Route
func (InstanceListRoute) Name() string {
	return "instance:list"
}

// Methods implements api.Route
func (InstanceListRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (InstanceListRoute) Path() string {
	return "/instances"
}

// RequireAuth implements the api.AuthorizedRoute
func (InstanceListRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (InstanceListRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeInstanceRead)
}

func instanceUpdate(ctx context.Context, params *InstanceUpdateParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	inst, err := ctrl.InstanceUpdate(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(inst)
}

// Name implements api.Route
func (InstanceUpdateRoute) Name() string {
	return "instance:update"
}

// Methods implements api.Route
func (InstanceUpdateRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (InstanceUpdateRoute) Path() string {
	return "/instances/{instance_id}"
}

// RequireAuth implements the api.AuthorizedRoute
func (InstanceUpdateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (InstanceUpdateRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeInstanceWrite)
}

func instanceDelete(ctx context.Context, params *InstanceDeleteParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	if err := ctrl.InstanceDelete(ctx, *params); err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}

// Name implements api.Route
func (InstanceDeleteRoute) Name() string {
	return "instance:delete"
}

// Methods implements api.Route
func (InstanceDeleteRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (InstanceDeleteRoute) Path() string {
	return "/instances/{instance_id}"
}

// RequireAuth implements the api.AuthorizedRoute
func (InstanceDeleteRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (InstanceDeleteRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeInstanceWrite)
}
