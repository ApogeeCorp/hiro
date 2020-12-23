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

const (
	// ScopeAudienceRead is used to read audience properties
	ScopeAudienceRead = "audience:read"

	// ScopeAudienceWrite is used to create or modify audiences
	ScopeAudienceWrite = "audience:write"

	// ScopeApplicationRead is used to read application properties
	ScopeApplicationRead = "application:read"

	// ScopeApplicationWrite is used to create or modify applications
	ScopeApplicationWrite = "application:write"

	// ScopeRoleRead is used to read roles
	ScopeRoleRead = "role:read"

	// ScopeRoleWrite is used to create or modify roles
	ScopeRoleWrite = "role:write"

	// ScopeUserRead is used to read users
	ScopeUserRead = "user:read"

	// ScopeUserWrite is used to create or modify users
	ScopeUserWrite = "user:write"

	// ScopeTokenRead is used to read request and access tokens
	ScopeTokenRead = "token:read"

	// ScopeTokenCreate is used to create access tokens
	ScopeTokenCreate = "token:create"

	// ScopeTokenRevoke is used to revoke request or access tokens
	ScopeTokenRevoke = "token:revoked"

	// ScopeSessionRead is used to read sessions
	ScopeSessionRead = "session:read"

	// SessionRevoke is used to destory sessions
	SessionRevoke = "session:destroy"
)
