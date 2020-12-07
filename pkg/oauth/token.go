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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// Token is a token secret
	Token struct {
		Algorithm TokenAlgorithm `json:"algorithm,omitempty"`
		Key       string         `json:"key,omitempty"`
		Lifetime  time.Duration  `json:"lifetime"`
		key       interface{}
	}

	// TokenAlgorithm is a token algorithm type
	TokenAlgorithm string
)

const (
	// TokenLifetimeMinimum is the minimum token lifetime
	TokenLifetimeMinimum = time.Minute

	// TokenAlgorithmRS256 is the RSA 256 token algorithm
	TokenAlgorithmRS256 TokenAlgorithm = "RS256"

	// TokenAlgorithmHS256 is the HMAC with SHA-256 token algorithm
	TokenAlgorithmHS256 TokenAlgorithm = "HS256"

	// TokenAlgorithmNone is used for updating other parameters
	TokenAlgorithmNone TokenAlgorithm = ""
)

// Validate handles validation for TokenAlgorithm types
func (a TokenAlgorithm) Validate() error {
	return validation.Validate(string(a), validation.In(string(TokenAlgorithmNone), string(TokenAlgorithmRS256), string(TokenAlgorithmHS256)))
}

// GenerateTokenSecret generates an RSA256 token and returns the encoded string value
func GenerateTokenSecret(alg TokenAlgorithm, lifetime time.Duration) (*Token, error) {
	token := &Token{
		Algorithm: alg,
		Lifetime:  lifetime,
	}

	switch alg {
	case TokenAlgorithmHS256:
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("%w: failed to generate random token", err)
		}
		token.key = key

	case TokenAlgorithmRS256:
		reader := rand.Reader
		key, err := rsa.GenerateKey(reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to generate rsa key", err)
		}
		token.key = key

	default:
		return nil, fmt.Errorf("unexpected token algorithm %s", alg)
	}

	return token, token.Validate()
}

// NewTokenSecret returns a token secret from the algorithm and key
func NewTokenSecret(alg TokenAlgorithm, key interface{}, lifetime time.Duration) (*Token, error) {
	token := &Token{
		Algorithm: alg,
		Lifetime:  lifetime,
		key:       key,
	}

	if alg == TokenAlgorithmRS256 {
		if data, ok := key.([]byte); ok {
			// parse the bytes
			key, err := jwt.ParseRSAPrivateKeyFromPEM(data)
			if err != nil {
				return nil, err
			}

			token.key = key
		}
	}

	return token, token.Validate()
}

// Validate handles validation of the TokenSecret struct
func (t Token) Validate() error {
	if err := (validation.Errors{
		"algorithm": validation.Validate(t.Algorithm),
		"lifetime":  validation.Validate(t.Lifetime, validation.Required, validation.Min(TokenLifetimeMinimum)),
	}).Filter(); err != nil {
		return err
	}

	switch t.Algorithm {
	case TokenAlgorithmHS256:
		if key, ok := t.key.([]byte); !ok || len(key) == 0 {
			return fmt.Errorf("HS256 requires a []byte key")
		}

	case TokenAlgorithmRS256:
		if key, ok := t.key.(*rsa.PrivateKey); !ok {
			if err := key.Validate(); err != nil {
				return fmt.Errorf("%w: rsa key validation failed", err)
			}

			return fmt.Errorf("RS256 requires an *rsa.PrivateKey key")
		}
	}

	return nil
}

// MarshalJSON marshals the token to json
func (t Token) MarshalJSON() ([]byte, error) {
	val := struct {
		Algorithm TokenAlgorithm `json:"algorithm,omitempty"`
		Key       string         `json:"key,omitempty"`
		Lifetime  time.Duration  `json:"lifetime"`
	}{
		Algorithm: t.Algorithm,
		Key:       base64.RawURLEncoding.EncodeToString(t.Bytes()),
		Lifetime:  t.Lifetime,
	}

	return json.Marshal(val)
}

// UnmarshalJSON unmarshals the token from json
func (t *Token) UnmarshalJSON(data []byte) error {
	val := struct {
		Algorithm  TokenAlgorithm `json:"algorithm"`
		EncodedKey string         `json:"key"`
		Lifetime   time.Duration  `json:"lifetime"`
	}{}

	if err := json.Unmarshal(data, &val); err != nil {
		return err
	}

	t.Algorithm = val.Algorithm
	t.Key = val.EncodedKey
	t.Lifetime = val.Lifetime
	
	if err := t.Algorithm.Validate(); err != nil {
		return err
	}

	key, err := base64.RawURLEncoding.DecodeString(t.Key)
	if err != nil {
		return fmt.Errorf("%w: failed to decode rsa token secret", err)
	}

	switch t.Algorithm {
	case TokenAlgorithmHS256:
		t.key = key

	case TokenAlgorithmRS256:
		if t.key, err = jwt.ParseRSAPrivateKeyFromPEM(key); err != nil {
			return err
		}
	}

	return nil
}

// Scan implements the Scanner interface.
func (t *Token) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}

	return nil
}

// Value implements the driver Valuer interface.
func (t Token) Value() (driver.Value, error) {
	return json.Marshal(t)
}

// Bytes returns the token as bytes
func (t Token) Bytes() []byte {
	switch key := t.key.(type) {
	case *rsa.PrivateKey:
		privOut := new(bytes.Buffer)
		privKey := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}

		if err := pem.Encode(privOut, privKey); err == nil {
			return privOut.Bytes()
		}

	case []byte:
		return key
	}

	return []byte{}
}
