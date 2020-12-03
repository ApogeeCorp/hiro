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

// Scope are used for both OAuth scopes and API ACL lists.
type Scope []string

// MakeScope returns a Permissions from the string scopes
func MakeScope(s ...string) Scope {
	return Scope(s)
}

// Contains return true if the scope contains the value
func (s Scope) Contains(value string) bool {
	for _, v := range s {
		if v == value {
			return true
		}
	}

	return false
}

// Every returns true if every element is contained in the scope
func (s Scope) Every(elements ...string) bool {
	for _, elem := range elements {
		if !s.Contains(elem) {
			return false
		}
	}
	return true
}

// Some returns true if at least one of the elements is contained in the scope
func (s Scope) Some(elements ...string) bool {
	for _, elem := range elements {
		if s.Contains(elem) {
			return true
		}
	}
	return false
}

// Without returns the scope excluding the elements
func (s Scope) Without(elements ...string) Scope {
	r := make(Scope, 0)
	for _, v := range s {
		if !Scope(elements).Contains(v) {
			r = append(r, v)
		}
	}

	return r
}

// Unique returns a scope withonly unique values
func (s Scope) Unique() Scope {
	keys := make(map[string]bool)
	list := []string{}

	for _, entry := range s {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// MarshalJSON handles json marshaling of this type
func (s Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(s.Unique()))
}

// Value returns Permissions as a value that can be stored as json in the database
func (s Scope) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// Scan reads a json value from the database into a Permissions
func (s *Scope) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	return nil
}
