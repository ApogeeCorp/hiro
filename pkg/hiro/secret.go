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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/dgrijalva/jwt-go"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// Secret is a secret key implemenation of oauth.TokenSecret
	Secret struct {
		ID         ID                    `json:"id" db:"id"`
		Type       SecretType            `json:"type"`
		AudienceID ID                    `json:"audience_id" db:"audience_id"`
		Algorithm  *oauth.TokenAlgorithm `json:"algorithm,omitempty" db:"algorithm"`
		Key        string                `json:"key" db:"key"`
		CreatedAt  time.Time             `json:"created_at" db:"created_at"`
		ExpiresAt  *time.Time            `json:"expires_at,omitempty" db:"expires_at"`
	}

	// SecretCreateInput is the params used to create a secret
	SecretCreateInput struct {
		AudienceID ID                    `json:"audience_id"`
		Type       SecretType            `json:"type"`
		Algorithm  *oauth.TokenAlgorithm `json:"algorithm,omitempty"`
		Key        *string               `json:"key,omitempty"`
		ExpiresAt  *time.Time            `json:"expires_at,omitempty"`
	}

	// SecretDeleteInput is the secret delete request input
	SecretDeleteInput struct {
		SecretID ID `json:"secret_id"`
	}

	// SecretType is a secret type
	SecretType string

	oauthSecret struct {
		*Secret
		key interface{}
	}
)

const (
	// SecretTypeToken are used for token signing
	SecretTypeToken SecretType = "token"

	// SecretTypeSession are used for session signing
	SecretTypeSession SecretType = "session"
)

// ValidateWithContext handles validation of the AudienceCreateInput struct
func (s SecretCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&s,
		validation.Field(&s.AudienceID, validation.Required),
		validation.Field(&s.Type, validation.Required, validation.In(SecretTypeToken, SecretTypeSession)),
		validation.Field(&s.Algorithm, validation.When(s.Type == SecretTypeToken, validation.Required).Else(validation.Nil)),
	)
}

// ValidateWithContext handles validation of the SecretDeleteInput
func (s SecretDeleteInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&s,
		validation.Field(&s.SecretID, validation.Required),
	)
}

// SecretCreate creates a new secret, generating the key if not is provided
func (b *Backend) SecretCreate(ctx context.Context, params SecretCreateInput) (*Secret, error) {
	var secret Secret

	log := b.Log(ctx).WithField("operation", "SecretCreate").WithField("secret_type", params.Type)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if params.Type == SecretTypeToken {
		if params.Key == nil {
			switch *params.Algorithm {
			case oauth.TokenAlgorithmHS256:
				key := make([]byte, 32)
				if _, err := rand.Read(key); err != nil {
					return nil, fmt.Errorf("%w: failed to generate random token", err)
				}
				params.Key = ptr.String(base64.RawURLEncoding.EncodeToString(key))

			case oauth.TokenAlgorithmRS256:
				reader := rand.Reader
				key, err := rsa.GenerateKey(reader, 2048)
				if err != nil {
					return nil, fmt.Errorf("%w: failed to generate rsa key", err)
				}

				privOut := new(bytes.Buffer)
				privKey := &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(key),
				}

				if err := pem.Encode(privOut, privKey); err != nil {
					return nil, fmt.Errorf("%w: failed to generate encoded pem", err)
				}

				params.Key = ptr.String(base64.RawURLEncoding.EncodeToString(privOut.Bytes()))

			default:
				return nil, fmt.Errorf("unexpected token algorithm %s", params.Algorithm)
			}
		} else {
			data, err := base64.RawURLEncoding.DecodeString(*params.Key)
			if err != nil {
				return nil, err
			}

			switch *params.Algorithm {
			case oauth.TokenAlgorithmHS256:
				if len(data) < 32 {
					return nil, errors.New("invalid hmac key length, must be greater than 32 bytes")
				}

			case oauth.TokenAlgorithmRS256:
				_, err := jwt.ParseRSAPrivateKeyFromPEM(data)
				if err != nil {
					return nil, err
				}
			}
		}
	} else {
		if params.Key == nil {
			key := make([]byte, 64)
			if _, err := rand.Read(key); err != nil {
				return nil, fmt.Errorf("%w: failed to generate random token", err)
			}
			params.Key = ptr.String(base64.RawURLEncoding.EncodeToString(key))
		} else {
			data, err := base64.RawURLEncoding.DecodeString(*params.Key)
			if err != nil {
				return nil, err
			}

			if len(data) < 64 {
				return nil, errors.New("invalid session key length, must be 64 bytes")
			}
		}
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new secert")

		stmt, args, err := sq.Insert("hiro.secrets").
			Columns(
				"audience_id",
				"type",
				"algorithm",
				"key",
				"expires_at").
			Values(
				params.AudienceID,
				params.Type,
				params.Algorithm,
				params.Key,
				params.ExpiresAt,
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(`RETURNING *`).
			ToSql()
		if err != nil {
			log.Error(err.Error())

			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &secret, stmt, args...); err != nil {
			log.Error(err.Error())

			return ParseSQLError(err)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	log.Debugf("secret %s created", secret.ID)

	return &secret, nil
}

// SecretDelete deletes an audience by id
func (b *Backend) SecretDelete(ctx context.Context, params SecretDeleteInput) error {
	log := b.Log(ctx).WithField("operation", "SecretDelete").WithField("audience", params.SecretID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)
	if _, err := sq.Delete("hiro.secrets").
		Where(
			sq.Eq{"id": params.SecretID},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to delete secret %s: %s", params.SecretID, err)
		return ParseSQLError(err)
	}

	return nil
}

func (s oauthSecret) ID() string {
	return s.Secret.ID.String()
}

func (s oauthSecret) Algorithm() oauth.TokenAlgorithm {
	return *s.Secret.Algorithm
}

func (s oauthSecret) Key() interface{} {
	return s.key
}

func (s oauthSecret) VerifyKey() interface{} {
	if s.Type != SecretTypeToken {
		return nil
	}

	switch *s.Secret.Algorithm {
	case oauth.TokenAlgorithmHS256:
		return s.key
	case oauth.TokenAlgorithmRS256:
		return &s.key.(*rsa.PrivateKey).PublicKey
	}

	return s.key
}

func (s oauthSecret) ExpiresAt() *time.Time {
	return s.Secret.ExpiresAt
}

// TokenSecret retuns a token secret from the Secret key
func TokenSecret(s *Secret) (oauth.TokenSecret, error) {
	var key interface{}

	data, err := base64.RawURLEncoding.DecodeString(s.Key)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode key data", err)
	}

	switch *s.Algorithm {
	case oauth.TokenAlgorithmHS256:
		key = data

	case oauth.TokenAlgorithmRS256:
		key, err = jwt.ParseRSAPrivateKeyFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode rsa token secret", err)
		}
	}

	return &oauthSecret{
		Secret: s,
		key:    key,
	}, nil
}
