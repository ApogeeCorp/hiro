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
	"strings"
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/dgrijalva/jwt-go"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/mitchellh/mapstructure"
	"github.com/patrickmn/go-cache"
)

type (
	// Token represents a revokable set of claims
	Token struct {
		ID         string   `json:"jti,omitempty"`
		Issuer     *string  `json:"iss,omitempty"`
		Subject    *string  `json:"sub,omitempty"`
		Audience   string   `json:"aud,omitempty"`
		ClientID   string   `json:"azp,omitempty"`
		Use        TokenUse `json:"use,omitempty"`
		AuthTime   int64    `json:"auth_time,omitempty"`
		Scope      Scope    `json:"scope,omitempty"`
		IssuedAt   int64    `json:"iat,omitempty"`
		ExpiresAt  *int64   `json:"exp,omitempty"`
		Revokable  bool     `json:"-"`
		Persistent bool     `json:"-"`
		RevokedAt  *int64   `json:"-"`
		Claims     Claims   `json:"-"`
		Bearer     *string  `json:"-"`
	}

	// TokenUse defines token usage
	TokenUse string
)

const (
	// TokenUseAccess is a token to be used for access
	TokenUseAccess TokenUse = "access"

	// TokenUseIdentity is a token to be used for identity
	TokenUseIdentity TokenUse = "identity"

	// TokenUseVerify is a token to be used for verification purposes
	TokenUseVerify TokenUse = "verify"
)

var (
	tokenCache = cache.New(time.Second*90, time.Minute*3)
)

// NewToken intializes a token of use type
func NewToken(use TokenUse) Token {
	return Token{
		Use:    use,
		Claims: make(Claims),
	}
}

// TokenFromClaims parse the claims into a Token
func TokenFromClaims(c Claims) (Token, error) {
	var t Token
	var meta mapstructure.Metadata

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:   &t,
		Metadata: &meta,
		TagName:  "json"})
	if err != nil {
		return t, err
	}

	if err := dec.Decode(c); err != nil {
		return t, err
	}

	for _, k := range meta.Unused {
		t.Claims[k] = c[k]
	}

	return t, t.Validate()
}

// Validate validates the token
func (t Token) Validate() error {
	return validation.ValidateStruct(&t,
		validation.Field(&t.ID, validation.Required),
		validation.Field(&t.Use, validation.Required),
		validation.Field(&t.Audience, validation.Required),
		validation.Field(&t.ClientID, validation.Required),
		validation.Field(&t.Issuer, validation.Required),
	)
}

// Sign generates an encoded and sign token using the secret
func (t Token) Sign(s TokenSecret) (string, error) {
	// create the full token claims
	enc := structs.New(t)
	enc.TagName = "json"

	c := Claims(enc.Map())

	for k, v := range t.Claims {
		c[k] = v
	}

	return c.Sign(s)
}

// Type implements the api.Principal interface
func (t Token) Type() api.PrincipalType {
	if t.Subject != nil {
		return api.PrincipalTypeUser
	}

	return api.PrincipalTypeApplication
}

// CredentialType implements the api.Principal interface
func (t Token) CredentialType() api.CredentialType {
	return api.CredentialTypeBearer
}

// Credentials implements the api.Principal interface
func (t Token) Credentials() string {
	return safe.String(*t.Bearer)
}

// AuthClaims implements the api.Principal interface
func (t Token) AuthClaims() api.Claims {
	return t.Claims
}

// Expired returns true of the token expires and is expired
func (t Token) Expired() bool {
	if t.ExpiresAt == nil {
		return false
	}

	return time.Unix(*t.ExpiresAt, 0).Before(time.Now())
}

// ParseBearer parses the jwt token into claims
func ParseBearer(bearer string, keyFn func(kid string, c Claims) (TokenSecret, error)) (Token, error) {
	var c Claims

	bearer = strings.TrimPrefix(bearer, "Bearer ")

	token, err := jwt.Parse(bearer, func(token *jwt.Token) (interface{}, error) {
		c = Claims(token.Claims.(jwt.MapClaims))

		secret, err := keyFn(token.Header["kid"].(string), c)
		if err != nil {
			return nil, err
		}

		return secret.VerifyKey(), nil
	})
	if err != nil {
		return Token{}, ErrInvalidToken.WithDetail(err.Error())
	}

	if !token.Valid {
		return Token{}, ErrInvalidToken
	}

	if t, ok := tokenCache.Get(c.ID()); ok {
		return t.(Token), nil
	}

	rval, err := TokenFromClaims(c)
	if err != nil {
		return Token{}, ErrInvalidToken.WithDetail(err)
	}

	rval.Bearer = ptr.String(bearer)

	tokenCache.Set(rval.ID, rval, cache.DefaultExpiration)

	return rval, nil
}

// Validate implements validation.Validatable interface
func (u TokenUse) Validate() error {
	return validation.Validate(string(u), validation.In("access", "identity", "verify"))
}

// Ptr returns a pointer to the use
func (u TokenUse) Ptr() *TokenUse {
	return &u
}
