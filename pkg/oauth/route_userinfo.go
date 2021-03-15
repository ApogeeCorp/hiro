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
	"context"
	"net/http"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/oauth/openid"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// UserInfoParams are the params for user info
	UserInfoParams struct{}

	// UserInfoRoute is the user info route
	UserInfoRoute func(ctx context.Context, params *UserInfoParams) api.Responder

	// UserInfoUpdateParams are the params to update the user profile
	UserInfoUpdateParams struct {
		*openid.Profile
	}

	// UserInfoUpdateRoute is the user info update route
	UserInfoUpdateRoute func(ctx context.Context, params *UserInfoUpdateParams) api.Responder
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

// Name implements api.Route
func (UserInfoRoute) Name() string {
	return "userinfo"
}

// Methods implements api.Route
func (UserInfoRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (UserInfoRoute) Path() string {
	return "/userinfo"
}

// RequireAuth implements the api.AuthorizedRoute
func (UserInfoRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (UserInfoRoute) Scopes() ScopeList {
	return BuildScope(ScopeOpenID, ScopeProfile)
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

// Name implements api.Route
func (UserInfoUpdateRoute) Name() string {
	return "userinfo-update"
}

// Methods implements api.Route
func (UserInfoUpdateRoute) Methods() []string {
	return []string{http.MethodPatch}
}

// Path implements api.Route
func (UserInfoUpdateRoute) Path() string {
	return "/userinfo"
}

// RequireAuth implements the api.AuthorizedRoute
func (UserInfoUpdateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (UserInfoUpdateRoute) Scopes() ScopeList {
	return BuildScope(ScopeOpenID, ScopeProfileWrite)
}
