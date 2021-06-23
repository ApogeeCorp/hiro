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
		return ErrUnauthorized.WithDetail("code verification failed")
	}

	return nil
}
