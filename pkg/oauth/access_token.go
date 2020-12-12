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
	"github.com/fatih/structs"
)

type (
	// AccessToken represents a revokable set of claims
	AccessToken struct {
		ID               types.ID   `json:"jti,omitempty" db:"id"`
		Subject          *types.ID  `json:"sub,omitempty" db:"user_id"`
		Audience         types.ID   `json:"aud,omitempty" db:"audience_id"`
		ClientID         types.ID   `json:"azp,omitempty" db:"application_id"`
		Use              TokenUse   `json:"use,omitempty" db:"token_use"`
		Scope            Scope      `json:"scope,omitempty" db:"scope"`
		IssuedAt         time.Time  `json:"iat,omitempty" db:"created_at"`
		ExpiresAt        *time.Time `json:"exp,omitempty" db:"expires_at"`
		RevokedAt        *time.Time `json:"-" db:"revoked_at"`
		AdditionalClaims Claims     `json:"-" db:"claims"`
	}

	// TokenUse defines token usage
	TokenUse string
)

const (
	// TokenUseAccess is a token to be used for access
	TokenUseAccess TokenUse = "access"

	// TokenUseIdentity is a token to be used for identity
	TokenUseIdentity TokenUse = "identity"
)

// Set sets a value in the claims
func (t *AccessToken) Set(key string, value interface{}) {
	if t.AdditionalClaims == nil {
		t.AdditionalClaims = make(Claims)
	}
	t.AdditionalClaims.Set(key, value)
}

// Claims returns the well-formed token as full set of claims
func (t *AccessToken) Claims() Claims {
	enc := structs.New(t)
	enc.TagName = "json"

	claims := Claims(enc.Map())

	for k, v := range t.AdditionalClaims {
		claims[k] = v
	}

	return claims
}
