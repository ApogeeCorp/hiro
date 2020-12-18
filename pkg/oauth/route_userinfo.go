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

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/oauth/openid"
	"github.com/ModelRocket/hiro/pkg/types"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// UserinfoParams are the params for user info
	UserinfoParams struct{}
)

// Validate validates the params
func (p UserinfoParams) Validate() error {
	return validation.ValidateStruct(&p)
}

func userinfo(ctx context.Context, params *UserinfoParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)
	claims := api.AuthContext(ctx).(Claims)

	user, err := ctrl.UserGet(ctx, types.ID(claims.Subject()))
	if err != nil {
		return api.ErrServerError.WithError(err)
	}

	profile := user.Profile()
	if profile != nil {
		if !claims.Scope().Contains("address") {
			profile.Address = nil
		}
		if !claims.Scope().Contains("phone") {
			profile.PhoneClaim = nil
		}
		if !claims.Scope().Contains("email") {
			profile.EmailClaim = nil
		}
	}

	if profile == nil {
		profile = &openid.Profile{}
	}

	return api.NewResponse(profile)
}
