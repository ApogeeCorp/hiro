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
	"crypto/sha256"
	"encoding/base64"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// CodeChallenge is a PKCE challenge code
	CodeChallenge string

	// CodeChallengeMethod defines a code challenge method
	CodeChallengeMethod string
)

const (
	// CodeChallengeMethodS256 is a sha-256 code challenge method
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

// Validate validates the CodeChallengeMethod
func (c CodeChallengeMethod) Validate() error {
	return validation.Validate(&c, validation.In(CodeChallengeMethodS256))
}

func (c CodeChallengeMethod) String() string {
	return string(c)
}

// Verify verifies the challenge against the base64 encoded verifier
func (c CodeChallenge) Verify(v string) error {
	sum := sha256.Sum256([]byte(v))
	check := base64.RawURLEncoding.EncodeToString(sum[:])

	if string(c) != check {
		return ErrAccessDenied.WithDetail("code verification failed")
	}

	return nil
}
