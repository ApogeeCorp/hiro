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
	"net/url"
	"path"

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

// String converts the uri to a string
func (u URI) String() string {
	return string(u)
}

// Ptr returns a pointer to the URI
func (u URI) Ptr() *URI {
	return &u
}

// Append appends the paths to the uri
func (u URI) Append(paths ...string) URI {
	v, _ := u.Parse()
	v.Path = path.Join(append([]string{path.Dir(v.Path)}, paths...)...)
	return URI(v.String())
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
