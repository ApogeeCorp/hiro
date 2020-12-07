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

type (
	// Scope is an oauth scope
	Scope string

	// ScopeList are used for both OAuth scopes and API ACL lists.
	ScopeList []Scope

	// ScopeSet represents a map between an audiece and a scope
	ScopeSet map[string]ScopeList
)

const (
	// ScopeOpenID is the openid scope
	ScopeOpenID Scope = "openid"

	// ScopeProfile is the scope required to query for a users profile
	ScopeProfile Scope = "profile"

	// ScopeOfflineAccess is the scope necessary to request a refresh_token
	ScopeOfflineAccess Scope = "offline_access"

	// ScopeVerifyEmail is the scope required to verify a user's email address
	ScopeVerifyEmail Scope = "verify:email"

	// ScopeVerifyPhone is the scope required to verify a user's phone number
	ScopeVerifyPhone Scope = "verify:phone"
)

var (
	// Scopes is the list of all oauth scopes
	Scopes = ScopeList{
		ScopeOpenID,
		ScopeProfile,
		ScopeOfflineAccess,
		ScopeVerifyEmail,
		ScopeVerifyPhone,
	}
)

// MakeScope returns a ScopeList from the string scopes
func MakeScope(s ...string) ScopeList {
	return ScopeList(s)
}

// Contains return true if the scope contains the value
func (s ScopeList) Contains(value string) bool {
	for _, v := range s {
		if v == value {
			return true
		}
	}

	return false
}

// Every returns true if every element is contained in the scope
func (s ScopeList) Every(elements ...string) bool {
	for _, elem := range elements {
		if !s.Contains(elem) {
			return false
		}
	}
	return true
}

// Some returns true if at least one of the elements is contained in the scope
func (s ScopeList) Some(elements ...string) bool {
	for _, elem := range elements {
		if s.Contains(elem) {
			return true
		}
	}
	return false
}

// Without returns the scope excluding the elements
func (s ScopeList) Without(elements ...string) ScopeList {
	r := make(ScopeList, 0)
	for _, v := range s {
		if !ScopeList(elements).Contains(v) {
			r = append(r, v)
		}
	}

	return r
}

// Unique returns a scope with only unique values
func (s ScopeList) Unique() ScopeList {
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
func (s ScopeList) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(s.Unique()))
}

// Value returns Permissions as a value that can be stored as json in the database
func (s ScopeList) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// Scan reads a json value from the database into a Permissions
func (s *ScopeList) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	return nil
}

// Get returns the scope for the audience
func (p ScopeSet) Get(a string) ScopeList {
	if s, ok := p[a]; ok {
		return s
	}
	return ScopeList{}
}

// Set sets a value in scope set
func (p ScopeSet) Set(a string, s ...string) {
	p[a] = s
}

// Value returns PermissionSet as a value that can be stored as json in the database
func (p ScopeSet) Value() (driver.Value, error) {
	perms := make(ScopeSet)
	for k, v := range p {
		perms[k] = v.Unique()
	}

	return json.Marshal(perms)
}

// Scan reads a json value from the database into a PermissionSet
func (p ScopeSet) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}

	return nil
}
