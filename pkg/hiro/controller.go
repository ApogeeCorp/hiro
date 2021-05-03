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

import (
	"context"

	"github.com/apex/log"
)

type (
	// Controller is the hiro API controller interface
	Controller interface {
		// API Controllers
		AudienceController
		SecretsController
		ApplicationController
		RoleController
		UserController
		AssetController

		// Log returns the log from the context
		Log(ctx context.Context) log.Interface

		// DBController provides db services
		DBController

		// PasswordManager is the password manager interface
		PasswordManager() PasswordManager
	}
)
