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
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// TokenSecret is a token secret interface
	TokenSecret interface {
		ID() string
		Algorithm() TokenAlgorithm
		Key() interface{}
		VerifyKey() interface{}
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
