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
	// UserCreateRoute is the user create route definition
	UserCreateRoute func(ctx context.Context, params *UserCreateInput) api.Responder

	// UserGetRoute is the user create route definition
	UserGetRoute func(ctx context.Context, params *UserGetInput) api.Responder

	// UserCountRoute is the user count route definition
	UserCountRoute func(ctx context.Context, params *UserListInput) api.Responder

	// UserListRoute is the user count route definition
	UserListRoute func(ctx context.Context, params *UserListInput) api.Responder

	// UserUpdateRoute is the user create route definition
	UserUpdateRoute func(ctx context.Context, params *UserUpdateInput) api.Responder

	// UserDeleteRoute is the user create route definition
	UserDeleteRoute func(ctx context.Context, params *UserDeleteInput) api.Responder
)

func userCreate(ctx context.Context, params *UserCreateInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	aud, err := ctrl.UserCreate(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(aud).WithStatus(http.StatusCreated)
}

func userGet(ctx context.Context, params *UserGetInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	aud, err := ctrl.UserGet(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(aud)
}

func userCount(ctx context.Context, params *UserListInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)
	var count uint64

	params.Offset = nil
	params.Limit = nil
	params.Count = &count

	_, err := ctrl.UserList(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithHeader("X-Query-Count", cast.ToString(params.Count))
}

func userList(ctx context.Context, params *UserListInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	auds, err := ctrl.UserList(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(auds).WithHeader("X-Query-Count", cast.ToString(len(auds)))
}

func userUpdate(ctx context.Context, params *UserUpdateInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	aud, err := ctrl.UserUpdate(ctx, *params)
	if err != nil {
		return api.Error(err)
	}

	return api.NewResponse(aud)
}

func userDelete(ctx context.Context, params *UserDeleteInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	if err := ctrl.UserDelete(ctx, *params); err != nil {
		return api.Error(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}

// Name implements api.Route
func (UserCreateRoute) Name() string {
	return "user:create"
}

// Methods implements api.Route
func (UserCreateRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (UserCreateRoute) Path() string {
	return "/users"
}

// RequireAuth implements the api.AuthorizedRoute
func (UserCreateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (UserCreateRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeUserWrite)
}

// Name implements api.Route
func (UserGetRoute) Name() string {
	return "user:get"
}

// Methods implements api.Route
func (UserGetRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (UserGetRoute) Path() string {
	return "/users"
}

// RequireAuth implements the api.AuthorizedRoute
func (UserGetRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (UserGetRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeUserRead)
}

// Name implements api.Route
func (UserCountRoute) Name() string {
	return "user:count"
}

// Methods implements api.Route
func (UserCountRoute) Methods() []string {
	return []string{http.MethodHead}
}

// Path implements api.Route
func (UserCountRoute) Path() string {
	return "/users"
}

// RequireAuth implements the api.AuthorizedRoute
func (UserCountRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (UserCountRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeUserRead)
}

// Name implements api.Route
func (UserListRoute) Name() string {
	return "user:list"
}

// Methods implements api.Route
func (UserListRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (UserListRoute) Path() string {
	return "/users"
}

// RequireAuth implements the api.AuthorizedRoute
func (UserListRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (UserListRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeUserRead)
}

// Name implements api.Route
func (UserUpdateRoute) Name() string {
	return "user:update"
}

// Methods implements api.Route
func (UserUpdateRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (UserUpdateRoute) Path() string {
	return "/users/{user_id}"
}

// RequireAuth implements the api.AuthorizedRoute
func (UserUpdateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (UserUpdateRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeUserWrite)
}

// Name implements api.Route
func (UserDeleteRoute) Name() string {
	return "user:delete"
}

// Methods implements api.Route
func (UserDeleteRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (UserDeleteRoute) Path() string {
	return "/users/{user_id}"
}

// RequireAuth implements the api.AuthorizedRoute
func (UserDeleteRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (UserDeleteRoute) Scopes() oauth.ScopeList {
	return oauth.BuildScope(ScopeUserWrite)
}
