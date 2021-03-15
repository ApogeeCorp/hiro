/*************************************************************************
 * MIT License
 * Copyright (c) 2021 Model Rocket
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
