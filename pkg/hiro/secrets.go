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

package hiro

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql/driver"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

type (
	// TokenSecret is a token secret
	TokenSecret struct {
		algorithm TokenAlgorithm
		key       interface{}
	}
)

// GenerateTokenSecret generates an RSA256 token and returns the encoded string value
func GenerateTokenSecret(alg TokenAlgorithm) (TokenSecret, error) {
	token := TokenSecret{
		algorithm: alg,
	}

	switch alg {
	case TokenAlgorithmHS256:
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return token, fmt.Errorf("%w: failed to generate random token", err)
		}
		token.key = key

	case TokenAlgorithmRS256:
		reader := rand.Reader
		key, err := rsa.GenerateKey(reader, 2048)
		if err != nil {
			return token, fmt.Errorf("%w: failed to generate rsa key", err)
		}
		token.key = key

	default:
		return token, fmt.Errorf("%w: unexpected token algorithm %s", ErrInputValidation, alg)
	}

	return token, nil
}

// Scan implements the Scanner interface.
func (t *TokenSecret) Scan(value interface{}) error {
	var encoded string

	switch v := value.(type) {
	case string:
		encoded = v

	case []byte:
		encoded = string(v)

	default:
		return fmt.Errorf("%w: unexpected input for TokenSecretRSA", ErrInputValidation)
	}

	d, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("%w: failed to decode rsa token secret", err)
	}

	if len(d) == 32 {
		t.key = d
		t.algorithm = TokenAlgorithmHS256
	} else {
		key, err := jwt.ParseRSAPrivateKeyFromPEM(d)
		if err != nil {
			return err
		}
		t.key = key
		t.algorithm = TokenAlgorithmRS256
	}

	return nil
}

// Value implements the driver Valuer interface.
func (t TokenSecret) Value() (driver.Value, error) {
	var data []byte

	switch key := t.key.(type) {
	case *rsa.PrivateKey:
		privOut := new(bytes.Buffer)
		privKey := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}

		if err := pem.Encode(privOut, privKey); err != nil {
			return nil, fmt.Errorf("%w: failed to encode pem", err)
		}

		data = privOut.Bytes()

	case []byte:
		data = key

	default:
		return nil, fmt.Errorf("%w: unexpected token key type %#v", ErrInputValidation, key)
	}

	return base64.RawURLEncoding.EncodeToString(data), nil
}
