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
	"reflect"
	"strings"
	"time"

	"errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/fatih/structs"
)

type (
	// Claims is generic map of token claims that may represent a jwt
	Claims map[string]interface{}
)

// Set implements the api.Claims interface
func (c Claims) Set(key string, value interface{}) {
	c[key] = value
}

// Get implements the api.Claims interface
func (c Claims) Get(key string) interface{} {
	return c[key]
}

// All implements the api.Claims interface
func (c Claims) All() map[string]interface{} {
	return map[string]interface{}(c)
}

// Delete delete the keys from the claim
func (c Claims) Delete(keys ...string) Claims {
	for _, key := range keys {
		delete(c, key)
	}
	return c
}

// ID returns the token id
func (c Claims) ID() string {
	if s, ok := c["jti"].(string); ok {
		return s
	}

	return ""
}

// Subject returns the subject for the token
func (c Claims) Subject() string {
	if s, ok := c["sub"].(string); ok {
		return s
	}

	return ""
}

// Scope returns the scope for the token
func (c Claims) Scope() Scope {
	if s, ok := c["scope"].(string); ok {
		return Scope(strings.Fields(s))
	}

	return make(Scope, 0)
}

// Audience returns the audience for the token
func (c Claims) Audience() string {
	if s, ok := c["aud"].(string); ok {
		return s
	}

	return ""
}

// ClientID returns the client id for the token
func (c Claims) ClientID() string {
	if s, ok := c["azp"].(string); ok {
		return s
	}

	return ""
}

// Use returns the token use
func (c Claims) Use() string {
	if s, ok := c["use"].(string); ok {
		return s
	}

	return ""
}

// IssuedAt returns the issue time for the token
func (c Claims) IssuedAt() time.Time {
	if s, ok := c["iat"].(int64); ok {
		return time.Unix(s, 0)
	}

	return time.Time{}
}

// ExpiresAt returns the expiration for the token
func (c Claims) ExpiresAt() time.Time {
	if s, ok := c["exp"].(int64); ok {
		return time.Unix(s, 0)
	}

	return time.Time{}
}

// Valid validates the claims
func (c Claims) Valid() error {
	return jwt.MapClaims(c).Valid()
}

// Value returns Map as a value that can be stored as json in the database
func (c Claims) Value() (driver.Value, error) {
	return json.Marshal(c)
}

// Scan reads a json value from the database into a Map
func (c Claims) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}

	return nil
}

// Encode encodes the value into a claims object
func (c *Claims) Encode(v interface{}) Claims {
	if *c == nil {
		*c = make(Claims)
	}

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr && val.IsNil() {
		return *c
	}

	enc := structs.New(v)
	enc.TagName = "json"

	for k, v := range enc.Map() {
		c.Set(k, v)
	}

	return *c
}

// Merge merges claims
func (c Claims) Merge(claims Claims) Claims {
	for k, v := range claims {
		c.Set(k, v)
	}

	return c
}

// Sign signs the claims using the token
func (c Claims) Sign(s TokenSecret) (string, error) {
	var token *jwt.Token

	switch s.Algorithm() {
	case TokenAlgorithmRS256:
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, c)

	case TokenAlgorithmHS256:
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, c)

	case TokenAlgorithmNone:
		token = jwt.NewWithClaims(jwt.SigningMethodNone, c)

	}

	token.Header["kid"] = s.ID()

	return token.SignedString(s.Key())
}
