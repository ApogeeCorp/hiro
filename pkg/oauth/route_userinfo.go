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
	var token Token

	ctrl := api.Context(ctx).(Controller)

	api.RequirePrincipal(ctx, &token, api.PrincipalTypeUser)

	user, err := ctrl.UserGet(ctx, *token.Subject)
	if err != nil {
		return api.ErrServerError.WithError(err)
	}

	profile := user.Profile()
	if profile != nil {
		if !token.Scope.Contains("address") {
			profile.Address = nil
		}
		if !token.Scope.Contains("phone") {
			profile.PhoneClaim = nil
		}
		if !token.Scope.Contains("email") {
			profile.EmailClaim = nil
		}
	}

	if profile == nil {
		profile = &openid.Profile{}
	}

	return api.NewResponse(profile)
}

func userinfoUpdate(ctx context.Context, params *UserInfoUpdateParams) api.Responder {
	var token Token

	ctrl := api.Context(ctx).(Controller)

	api.RequirePrincipal(ctx, &token)

	if params.Profile.Address != nil && !token.Scope.Contains("address") {
		return api.ErrForbidden
	}

	if params.PhoneNumberVerified != nil && !token.Scope.Contains("phone:verify") {
		return api.ErrForbidden.WithDetail("phone:verify scope required")
	}
	if params.Profile.PhoneClaim != nil && !token.Scope.Contains("phone") {
		return api.ErrForbidden
	}

	if params.EmailVerified != nil && !token.Scope.Contains("email:verify") {
		return api.ErrForbidden.WithDetail("email:verify scope required")
	}
	if params.Profile.EmailClaim != nil && !token.Scope.Contains("email") {
		return api.ErrForbidden
	}

	if err := ctrl.UserUpdate(ctx, *token.Subject, params.Profile); err != nil {
		return api.ErrServerError.WithError(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}
