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
	"context"
	"crypto/rsa"

	"github.com/ModelRocket/hiro/pkg/api"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"gopkg.in/square/go-jose.v2"
)

type (
	// JWKSInput is the input for the jwks route
	JWKSInput struct {
		Audience []string `json:"audience"`
	}
)

// Validate validates the JWKSInput struct
func (j JWKSInput) Validate() error {
	return validation.ValidateStruct(&j,
		validation.Field(&j.Audience, validation.Required))
}

func jwks(ctx context.Context, params *JWKSInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	keys := make([]jose.JSONWebKey, 0)

	for _, id := range params.Audience {
		aud, err := ctrl.AudienceGet(ctx, id)
		if err != nil {
			return ErrAudienceNotFound.WithError(err)
		}

		if aud.Secret().Algorithm != TokenAlgorithmRS256 {
			return api.ErrBadRequest.WithMessage("audience does not support rsa tokens")
		}

		key := jose.JSONWebKey{
			KeyID:     aud.ID().String(),
			Key:       &aud.Secret().key.(*rsa.PrivateKey).PublicKey,
			Algorithm: aud.Secret().Algorithm.String(),
			Use:       "sig",
		}

		keys = append(keys, key)
	}

	return api.NewResponse(jose.JSONWebKeySet{
		Keys: keys,
	})
}
