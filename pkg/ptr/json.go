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

package ptr

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"

	"github.com/go-openapi/errors"
)

// JSON is json pointer
type JSON struct {
	json.RawMessage
	valid bool
}

// MarshalJSON marshals the object to json
func (j JSON) MarshalJSON() ([]byte, error) {
	if j.valid == false {
		return []byte("{}"), nil
	}
	return json.Marshal(j.RawMessage)
}

// Value returns Map as a value that can be stored as json in the database
func (j JSON) Value() (driver.Value, error) {
	if j.valid == false {
		return nil, nil
	}

	return json.Marshal(j.RawMessage)
}

// Scan reads a json value from the database into a Map
func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return errors.New(http.StatusInternalServerError, "type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &j.RawMessage); err != nil {
		return err
	}

	j.valid = true

	return nil
}
