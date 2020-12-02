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
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// Permissions are used for both OAuth scopes and API ACL lists.
type Permissions []string

// MakePermissions returns a Permissions from the string scopes
func MakePermissions(s ...string) Permissions {
	return Permissions(s)
}

// Contains return true if the scope contains the value
func (p Permissions) Contains(value string) bool {
	for _, v := range p {
		if v == value {
			return true
		}
	}

	return false
}

// Every returns true if every element is contained in the scope
func (p Permissions) Every(elements ...string) bool {
	for _, elem := range elements {
		if !p.Contains(elem) {
			return false
		}
	}
	return true
}

// Some returns true if at least one of the elements is contained in the scope
func (p Permissions) Some(elements ...string) bool {
	for _, elem := range elements {
		if p.Contains(elem) {
			return true
		}
	}
	return false
}

// Without returns the scope excluding the elements
func (p Permissions) Without(elements ...string) Permissions {
	r := make(Permissions, 0)
	for _, v := range p {
		if !Permissions(elements).Contains(v) {
			r = append(r, v)
		}
	}

	return r
}

// Value returns Permissions as a value that can be stored as json in the database
func (p Permissions) Value() (driver.Value, error) {
	return json.Marshal(p)
}

// Scan reads a json value from the database into a Permissions
func (p Permissions) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}

	return nil
}
