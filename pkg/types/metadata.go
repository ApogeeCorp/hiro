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

package types

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

type (
	// Metadata Metadata is a basic hash type
	Metadata map[string]interface{}
)

// Validate validates this map
func (m Metadata) Validate() error {
	return nil
}

// Value returns Map as a value that can be stored as json in the database
func (m Metadata) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a Map
func (m Metadata) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	return nil
}
