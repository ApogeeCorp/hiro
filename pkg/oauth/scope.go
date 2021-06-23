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
	"strings"
)

type (
	// Scope is an oauth scope
	Scope []string

	// ScopeList is used to build scopes
	ScopeList struct {
		list []Scope
	}
)

const (
	// ScopeOpenID is the openid scope
	ScopeOpenID = "openid"

	// ScopeProfile is the scope required to query for a users profile
	ScopeProfile = "profile"

	// ScopeProfileWrite is the scope required to write to a users profile
	ScopeProfileWrite = "profile:write"

	// ScopeOfflineAccess is the scope necessary to request a refresh_token
	ScopeOfflineAccess = "offline_access"

	// ScopeAddress is required to read a user's physical address
	ScopeAddress = "address"

	// ScopeEmail is the scope require to get a user's email address
	ScopeEmail = "email"

	// ScopeEmailVerify is the scope required to verify a user's email address
	ScopeEmailVerify = "emai:verify"

	// ScopePhone is the scope required to verify the user's phone number
	ScopePhone = "phone"

	// ScopePhoneVerify is the scope required to verify a user's phone number
	ScopePhoneVerify = "phone:verify"

	// ScopeTokenRead is provided for token introspection
	ScopeTokenRead = "token:read"

	// ScopeTokenRevoke is required for token revocation
	ScopeTokenRevoke = "token:revoke"

	// ScopeSession creates a login session
	ScopeSession = "session"

	// ScopePassword allows a user to set their password
	ScopePassword = "password"
)

var (
	// Scopes is the list of all oauth scopes
	// verify scopes have special use and should not be granted to users implicitly
	Scopes = Scope{
		ScopeOpenID,
		ScopeProfile,
		ScopeProfileWrite,
		ScopeOfflineAccess,
		ScopeAddress,
		ScopeEmail,
		ScopeEmailVerify,
		ScopePhone,
		ScopePhoneVerify,
		ScopeTokenRead,
		ScopeTokenRevoke,
	}
)

// BuildScope returns a []Scope from the string scope values
func BuildScope(scopes ...string) ScopeList {
	l := ScopeList{
		list: make([]Scope, 0),
	}

	if len(scopes) > 0 {
		l.list = append(l.list, Scope(scopes))
	}

	return l
}

// Or adds an or to the list
func (s ScopeList) Or(scopes ...string) ScopeList {
	s.list = append(s.list, scopes)
	return s
}

// And appends the scopes to the tail Scope on the list
func (s ScopeList) And(scopes ...string) ScopeList {
	s.list[len(s.list)-1] = append(s.list[len(s.list)-1], scopes...)
	return s
}

// Every checks if any of the scopes in the list have all of the scopes
func (s ScopeList) Every(scopes ...string) bool {
	for _, ss := range s.list {
		if ss.Every(scopes...) {
			return true
		}
	}

	return false
}

// Some checks if any of the scopes in the list have any of the scopes
func (s ScopeList) Some(scopes ...string) bool {
	for _, ss := range s.list {
		if ss.Some(scopes...) {
			return true
		}
	}

	return false
}

func (s ScopeList) String() string {
	rval := make([]string, 0)

	for _, l := range s.list {
		rval = append(rval, l...)
	}

	return strings.Join(rval, " ")
}

func (s ScopeList) Check(scope Scope) bool {
	for _, l := range s.list {
		if scope.Every(l...) {
			return true
		}
	}

	return false
}

// Contains return true if the scope contains the value
func (s Scope) Contains(value string) bool {
	for _, v := range s {
		if string(v) == value {
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

// Append appends to a scope
func (s Scope) Append(e ...string) Scope {
	return append(s, e...)
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

// Unique returns a scope with only unique values
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

// UnmarshalText handles text unmarshaling
func (s *Scope) UnmarshalText(v []byte) error {
	input := string(v)
	if strings.Contains(input, ",") {
		*s = strings.Split(input, ",")
	} else {
		*s = strings.Fields(input)
	}

	return nil
}

// MarshalJSON handles json marshaling of this type
func (s Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.Join([]string(s.Unique()), " "))
}

// Value returns Permissions as a value that can be stored as json in the database
func (s Scope) Value() (driver.Value, error) {
	return json.Marshal([]string(s.Unique()))
}

// Scan reads a json value from the database into a Permissions
func (s *Scope) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	val := make([]string, 0)
	if err := json.Unmarshal(b, &val); err != nil {
		return err
	}
	*s = val

	return nil
}

func (s *Scope) String() string {
	if s == nil {
		return ""
	}
	return strings.Join([]string(*s), " ")
}
