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
	"reflect"
	"strings"
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/dgrijalva/jwt-go"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/mitchellh/mapstructure"
)

type (
	// Token represents a revokable set of claims
	Token struct {
		ID        *string  `json:"jti,omitempty"`
		Issuer    *URI     `json:"iss,omitempty"`
		Subject   *string  `json:"sub,omitempty"`
		Audience  string   `json:"aud,omitempty"`
		ClientID  string   `json:"azp,omitempty"`
		Use       TokenUse `json:"use,omitempty"`
		AuthTime  *Time    `json:"auth_time,omitempty"`
		Scope     Scope    `json:"scope,omitempty"`
		IssuedAt  Time     `json:"iat,omitempty"`
		ExpiresAt *Time    `json:"exp,omitempty"`
		Revokable bool     `json:"-"`
		RevokedAt *Time    `json:"-"`
		Claims    Claims   `json:"-"`
		Bearer    *string  `json:"-"`
	}

	// TokenUse defines token usage
	TokenUse string
)

const (
	// TokenUseAccess is a token to be used for access
	TokenUseAccess TokenUse = "access"

	// TokenUseIdentity is a token to be used for identity
	TokenUseIdentity TokenUse = "identity"
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
		TagName:  "json",
		DecodeHook: func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
			if t == reflect.TypeOf(Time{}) && f.Kind() == reflect.Float64 {
				return Time(time.Unix(int64(data.(float64)), 0)), nil
			}
			if t.Kind() == reflect.Slice && f.Kind() == reflect.String {
				raw := data.(string)
				if raw == "" {
					return []string{}, nil
				}
				return strings.Split(raw, " "), nil
			}
			return data, nil
		},
	})
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

// ParseBearer parses the jwt token into claims
func ParseBearer(bearer string, keyFn func(c Claims) (TokenSecret, error)) (Token, error) {
	var c Claims

	token, err := jwt.Parse(bearer, func(token *jwt.Token) (interface{}, error) {
		c = Claims(token.Claims.(jwt.MapClaims))

		secret, err := keyFn(c)
		if err != nil {
			return nil, err
		}

		return secret.VerifyKey(), nil
	})
	if err != nil {
		return Token{}, ErrInvalidToken.WithDetail(err)
	}

	if !token.Valid {
		return Token{}, ErrInvalidToken
	}

	rval, err := TokenFromClaims(c)
	if err != nil {
		return Token{}, ErrInvalidToken.WithDetail(err)
	}

	rval.Bearer = ptr.String(bearer)

	return rval, nil
}
