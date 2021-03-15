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

package oauth

import (
	"database/sql/driver"
	"encoding/json"
	"errors"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// GrantType is an oauth grant type
	GrantType string

	// GrantList is a list of grants
	GrantList []GrantType

	// Grants is a mapping of grants to audiece
	Grants map[string]GrantList
)

const (
	// GrantTypeNone is used to filter Authorization parameters
	GrantTypeNone GrantType = "none"

	// GrantTypeAuthCode is the authorization_code grant type
	GrantTypeAuthCode GrantType = "authorization_code"

	// GrantTypeClientCredentials is the client_credentials grant type
	GrantTypeClientCredentials GrantType = "client_credentials"

	// GrantTypePassword is the password grant type
	GrantTypePassword GrantType = "password"

	// GrantTypeRefreshToken is the refresh_token grant type
	GrantTypeRefreshToken GrantType = "refresh_token"
)

// Validate handles validation for GrantType
func (g GrantType) Validate() error {
	return validation.Validate(string(g), validation.In("authorization_code", "client_credentials", "password", "refresh_token"))
}

// Contains return true if the scope contains the value
func (g GrantList) Contains(value GrantType) bool {
	for _, v := range g {
		if v == value {
			return true
		}
	}

	return false
}

// Unique returns a scope withonly unique values
func (g GrantList) Unique() GrantList {
	keys := make(map[GrantType]bool)
	list := []GrantType{}

	for _, entry := range g {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// Validate validates the Grants type
func (g Grants) Validate() error {
	return validation.Validate(map[string]GrantList(g), validation.Each())
}

// Get returns the scope for the audience
func (g Grants) Get(a string) GrantList {
	if l, ok := g[a]; ok {
		return l
	}
	return GrantList{}
}

// Set sets a value in scope set
func (g Grants) Set(a string, t ...GrantType) {
	g[a] = t
}

// Append appends to the scope set
func (g Grants) Append(a string, t ...GrantType) {
	if g[a] == nil {
		g[a] = make(GrantList, 0)
	}
	g[a] = append(g[a], t...)
}

// Value returns PermissionSet as a value that can be stored as json in the database
func (g Grants) Value() (driver.Value, error) {
	grants := make(Grants)
	for k, v := range g {
		grants[k] = v.Unique()
	}

	return json.Marshal(grants)
}

// Scan reads a json value from the database into a PermissionSet
func (g Grants) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &g); err != nil {
		return err
	}

	return nil
}
