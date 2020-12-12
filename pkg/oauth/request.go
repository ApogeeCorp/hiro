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
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// Request represents an oauth request used for authorization_code and refresh_token flows
	Request struct {
		ID                  types.ID            `db:"id"`
		CreatedAt           time.Time           `db:"created_at"`
		AudienceID          types.ID            `db:"audience_id"`
		ApplicationID       types.ID            `db:"application_id,"`
		Scope               Scope               `db:"scope,omitempty"`
		ExpiresAt           time.Time           `db:"expires_at"`
		CodeChallenge       string              `db:"code_challenge"`
		CodeChallengeMethod CodeChallengeMethod `db:"code_challenge_method"`
		AppURI              URI                 `db:"app_uri"`
		RedirectURI         URI                 `db:"redirect_uri"`
		State               *string             `db:"state,omitempty"`
	}

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

// Validate validates the Request
func (r Request) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.AudienceID, validation.Required),
		validation.Field(&r.ApplicationID, validation.Required),
		validation.Field(&r.CodeChallenge, validation.Required),
		validation.Field(&r.CodeChallengeMethod, validation.Required),
		validation.Field(&r.ExpiresAt, validation.Required),
		validation.Field(&r.AppURI, validation.Required, is.RequestURI),
		validation.Field(&r.RedirectURI, validation.Required, is.RequestURI),
		validation.Field(&r.Scope, validation.Required),
		validation.Field(&r.State, validation.NilOrNotEmpty),
	)
}
