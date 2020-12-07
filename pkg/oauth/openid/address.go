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

package openid

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// Address OpenID address claim as defined in section 5.1.1 of the connect core 1.0 specification
type Address struct {

	// Country name component.
	Country *string `json:"country,omitempty"`

	// Full mailing address, formatted for display or use on a mailing label. This field MAY contain multiple lines, separated by newlines.
	// Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
	//
	Formatted *string `json:"formatted,omitempty"`

	// City or locality component.
	Locality *string `json:"locality,omitempty"`

	// Zip code or postal code component.
	PostalCode *string `json:"postal_code,omitempty"`

	// State, province, prefecture, or region component.
	Region *string `json:"region,omitempty"`

	// Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended street address
	// information. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line
	// feed pair ("\r\n") or as a single line feed character ("\n").
	//
	StreetAddress *string `json:"street_address,omitempty"`
}

// Validate handles validation for the Profile struct
func (a Address) Validate() error {
	return nil
}

// Value returns Address as a value that can be stored as json in the database
func (a Address) Value() (driver.Value, error) {
	return json.Marshal(a)
}

// Scan reads a json value from the database into a Address
func (a *Address) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}

	return nil
}
