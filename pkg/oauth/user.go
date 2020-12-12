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

package oauth

import (
	"context"

	"github.com/ModelRocket/hiro/pkg/types"
)

type (
	// User is an oauth user interface
	User interface {
		UserID() types.ID

		// UserAuthorize authorizes the user for the specified grants, uris, and scopes
		// Used for authorization_code flows
		UserAuthorize(ctx context.Context, aud string, scopes ...Scope) error
	}
)
