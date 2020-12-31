/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://githuh.com/ModelRocket/hiro
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
	"time"
	"unicode"

	"github.com/ModelRocket/sparks/pkg/oauth"
	"golang.org/x/crypto/bcrypt"
)

type (
	// PasswordManager is an interface for hashing and validation of passwords
	PasswordManager interface {
		HashPassword(password string) (string, error)
		CheckPasswordHash(password, hash string) bool
		EnforcePasswordPolicy(enabled bool)
		ValidatePassword(password string) error
		PasswordExpiry() time.Duration
		MaxLoginAttempts() int
		AccountLockoutPeriod() time.Duration
	}

	passwordManager struct {
		validationEnabled bool
	}
)

const (
	// MaxPasswordAge is the max age of a password before it must be changed
	MaxPasswordAge = time.Hour * 24 * 90
)

var (
	// DefaultPasswordManager is the default password manager
	DefaultPasswordManager = passwordManager{}
)

// HashPassword generats a bcrypt password hash
func (passwordManager) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash validates two passwords match
func (passwordManager) CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (passwordManager) MaxLoginAttempts() int {
	return 10
}

func (passwordManager) AccountLockoutPeriod() time.Duration {
	return time.Minute * 10
}

// EnforcePasswordPolicy enables password validation
func (p passwordManager) EnforcePasswordPolicy(enabled bool) {
	p.validationEnabled = enabled
}

// ValidatePassword should be used by the backed to ensure passwords meet organization standards
// This service requires passwords 8-64 characters in length, 1 uppercase, 1 lowercase, 1 digit,
// and 1 special character.
func (p passwordManager) ValidatePassword(password string) error {
	const minPassLength = 8
	const maxPassLength = 64

	if !p.validationEnabled {
		return nil
	}

	if len(password) < minPassLength || len(password) > maxPassLength {
		return oauth.ErrPasswordLen
	}

	var uppercasePresent bool
	var lowercasePresent bool
	var numberPresent bool
	var specialCharPresent bool

	for _, ch := range password {
		switch {
		case unicode.IsNumber(ch):
			numberPresent = true
		case unicode.IsUpper(ch):
			uppercasePresent = true
		case unicode.IsLower(ch):
			lowercasePresent = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			specialCharPresent = true
		}
	}

	if !(lowercasePresent && uppercasePresent && numberPresent && specialCharPresent) {
		return oauth.ErrPasswordComplexity
	}

	return nil
}

// PasswordExpiry returns the default password expiration from now
func (passwordManager) PasswordExpiry() time.Duration {
	return MaxPasswordAge
}
