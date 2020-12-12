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
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// LoginParams contains all the bound params for the login operation
	LoginParams struct {
		Login        string `json:"login"`
		Password     string `json:"password"`
		RequestToken string `json:"request_token"`
	}
)

// Validate validates LoginParams
func (p LoginParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Login, validation.Required),
		validation.Field(&p.Password, validation.Required),
		validation.Field(&p.RequestToken, validation.Required),
	)
}

func login(ctx context.Context, params *LoginParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)
	//log := api.Log(ctx).WithField("operation", "login")

	req, err := ctrl.RequestTokenGet(ctx, params.RequestToken)
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	if req.ExpiresAt.Before(time.Now()) {
		return ErrExpiredToken
	}

	if req.Type != RequestTokenTypeAuthCode {
		return ErrInvalidToken
	}

	

	return nil
}
