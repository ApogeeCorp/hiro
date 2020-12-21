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
	"time"

	"github.com/ModelRocket/hiro/pkg/types"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// TokenSecret is a token secret interface
	TokenSecret interface {
		ID() types.ID
		Algorithm() TokenAlgorithm
		Key() interface{}
		ExpiresAt() *time.Time
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

func (a TokenAlgorithm) String() string {
	return string(a)
}

// Ptr returns a pointer to the algorithm
func (a TokenAlgorithm) Ptr() *TokenAlgorithm {
	return &a
}
