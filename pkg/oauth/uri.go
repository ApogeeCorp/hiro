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
	"net/url"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// URI is a uri
	URI string

	// URIList is a list of uris
	URIList []URI
)

// MakeURIList returns a Scope from the string scopes
func MakeURIList(uris ...string) URIList {
	l := make(URIList, 0)
	for _, u := range uris {
		l = append(l, URI(u))
	}
	return l
}

// Validate validates a uri
func (u URI) Validate() error {
	return validation.Validate(string(u), is.RequestURI)
}

// Parse parses the uri into a url.URL
func (u URI) Parse() (*url.URL, error) {
	return url.Parse(string(u))
}

// Unique returns a scope withonly unique values
func (u URIList) Unique() URIList {
	keys := make(map[URI]bool)
	list := []URI{}

	for _, entry := range u {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// MarshalJSON handles json marshaling of this type
func (u URIList) MarshalJSON() ([]byte, error) {
	rval := make([]string, 0)
	for _, t := range u.Unique() {
		rval = append(rval, string(t))
	}
	return json.Marshal(rval)
}

// Value returns Permissions as a value that can be stored as json in the database
func (u URIList) Value() (driver.Value, error) {
	return json.Marshal(u)
}

// Scan reads a json value from the database into a PermissionSet
func (u *URIList) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &u); err != nil {
		return err
	}

	return nil
}
