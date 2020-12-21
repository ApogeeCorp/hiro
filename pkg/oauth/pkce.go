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
	// PKCEChallenge is a PKCE challenge code
	PKCEChallenge string

	// PKCEChallengeMethod defines a code challenge method
	PKCEChallengeMethod string
)

const (
	// PKCEChallengeMethodNone is used to specify no challenge
	PKCEChallengeMethodNone PKCEChallengeMethod = "none"

	// PKCEChallengeMethodS256 is a sha-256 code challenge method
	PKCEChallengeMethodS256 PKCEChallengeMethod = "S256"
)

// Validate validates the CodeChallengeMethod
func (c PKCEChallengeMethod) Validate() error {
	return validation.Validate(string(c), validation.In("none", "S256"))
}

func (c PKCEChallengeMethod) String() string {
	return string(c)
}

// Verify verifies the challenge against the base64 encoded verifier
func (c PKCEChallenge) Verify(v string) error {
	sum := sha256.Sum256([]byte(v))
	check := base64.RawURLEncoding.EncodeToString(sum[:])

	if string(c) != check {
		return ErrAccessDenied.WithDetail("code verification failed")
	}

	return nil
}
