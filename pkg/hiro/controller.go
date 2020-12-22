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

package hiro

import "context"

type (
	// Controller is the hiro API controller interface
	Controller interface {
		// Audience interface
		AudienceCreate(ctx context.Context, params AudienceCreateInput) (*Audience, error)
		AudienceGet(ctx context.Context, params AudienceGetInput) (*Audience, error)
		AudienceList(ctx context.Context, params AudienceListInput) ([]*Audience, error)
		AudienceUpdate(ctx context.Context, params AudienceUpdateInput) (*Audience, error)
		AudienceDelete(ctx context.Context, params AudienceDeleteInput) error

		// Secrets interface
		SecretCreate(ctx context.Context, params SecretCreateInput) (*Secret, error)
		SecretDelete(ctx context.Context, params SecretDeleteInput) error

		// Application interface
		ApplicationCreate(ctx context.Context, params ApplicationCreateInput) (*Application, error)
		ApplicationGet(ctx context.Context, params ApplicationGetInput) (*Application, error)
		ApplicationList(ctx context.Context, params ApplicationListInput) ([]*Application, error)
		ApplicationUpdate(ctx context.Context, params ApplicationUpdateInput) (*Application, error)
		ApplicationDelete(ctx context.Context, params ApplicationDeleteInput) error

		// Role interface
		RoleCreate(ctx context.Context, params RoleCreateInput) (*Role, error)
		RoleGet(ctx context.Context, params RoleGetInput) (*Role, error)
		RoleList(ctx context.Context, params RoleListInput) ([]*Role, error)
		RoleUpdate(ctx context.Context, params RoleUpdateInput) (*Role, error)
		RoleDelete(ctx context.Context, params RoleDeleteInput) error

		// User interface
		UserCreate(ctx context.Context, params UserCreateInput) (*User, error)
		UserGet(ctx context.Context, params UserGetInput) (*User, error)
		UserList(ctx context.Context, params UserListInput) ([]*User, error)
		UserUpdate(ctx context.Context, params UserUpdateInput) (*User, error)
		UserDelete(ctx context.Context, params UserDeleteInput) error
	}
)
