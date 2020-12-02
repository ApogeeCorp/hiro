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
	"database/sql/driver"
	"errors"

	"github.com/google/uuid"
)

type (
	// UUID represents a uuid that may be null.
	UUID struct {
		UUID  uuid.UUID
		Valid bool // Valid is true if UUID is not NULL
	}
)

// MakeUUID safely converts s to a null.UUID
func MakeUUID(u interface{}) UUID {
	var rval UUID

	rval.Scan(u)

	return rval
}

// Scan implements the Scanner interface.
func (u *UUID) Scan(value interface{}) error {
	var err error

	if value == nil {
		u.Valid = false
		return nil
	}

	switch s := value.(type) {
	case string:
		u.UUID, err = uuid.Parse(s)
		if err != nil {
			return err
		}

	case []byte:
		u.UUID, err = uuid.ParseBytes(s)
		if err != nil {
			return err
		}

	default:
		return errors.New("unexpected type for null.UUID")
	}

	u.Valid = true

	return nil
}

// Value implements the driver Valuer interface.
func (u UUID) Value() (driver.Value, error) {
	if !u.Valid {
		return nil, nil
	}
	return u.UUID, nil
}
