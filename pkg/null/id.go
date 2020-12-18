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

package null

import (
	"database/sql"

	"github.com/ModelRocket/hiro/pkg/types"
)

// ID returns a pointer to the id
func ID(id interface{}) sql.NullString {
	switch t := id.(type) {
	case types.ID:
		return String(t.String())

	case *types.ID:
		if t != nil {
			return String(t.String())
		}
	}

	return String(id)
}
