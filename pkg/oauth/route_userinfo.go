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
	"net/http"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/oauth/openid"
	"github.com/ModelRocket/hiro/pkg/types"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// UserInfoParams are the params for user info
	UserInfoParams struct{}

	// UserInfoUpdateParams are the params to update the user profile
	UserInfoUpdateParams struct {
		*openid.Profile
	}
)

// Validate validates the params
func (p UserInfoParams) Validate() error {
	return validation.ValidateStruct(&p)
}

// Validate validates the params
func (p UserInfoUpdateParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Profile, validation.Required))
}

func userinfo(ctx context.Context, params *UserInfoParams) api.Responder {
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

func userinfoUpdate(ctx context.Context, params *UserInfoUpdateParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)
	claims := api.AuthContext(ctx).(Claims)

	if params.Profile.Address != nil && !claims.Scope().Contains("address") {
		return ErrAccessDenied
	}

	if params.PhoneNumberVerified != nil && !claims.Scope().Contains("phone:verify") {
		return ErrAccessDenied.WithDetail("phone:verify scope required")
	}
	if params.Profile.PhoneClaim != nil && !claims.Scope().Contains("phone") {
		return ErrAccessDenied
	}

	if params.EmailVerified != nil && !claims.Scope().Contains("email:verify") {
		return ErrAccessDenied.WithDetail("email:verify scope required")
	}
	if params.Profile.EmailClaim != nil && !claims.Scope().Contains("email") {
		return ErrAccessDenied
	}

	if err := ctrl.UserUpdate(ctx, types.ID(claims.Subject()), params.Profile); err != nil {
		return api.ErrServerError.WithError(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}
