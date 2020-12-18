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
	"github.com/ModelRocket/hiro/pkg/api"
)

// Routes returns the oauth api routes
func Routes(ctrl Controller) []api.Route {
	auth := NewAuthorizer(ctrl, WithPermitQueryToken(true))

	return []api.Route{
		api.NewRoute("/authorize").Get().Handler(authorize).Context(ctrl),
		api.NewRoute("/login").Post().Handler(login).Context(ctrl),
		api.NewRoute("/logout").Get().Handler(logout).Context(ctrl),
		api.NewRoute("/signup").Post().Handler(signup).Context(ctrl),
		api.NewRoute("/token").Post().Handler(token).Context(ctrl),
		api.NewRoute("/userinfo").Get().Handler(userinfo).Context(ctrl).Authorizers(auth.AuthorizeScope("openid", "profile")),
		api.NewRoute("/userinfo").Patch().Handler(userinfoUpdate).Context(ctrl).Authorizers(auth.AuthorizeScope("openid", "profile")),
		api.NewRoute("/openid/{audience_id}/.well-known/openid-configuration").Get().Handler(openidConfig).Context(ctrl),
		api.NewRoute("/openid/{audience_id}/.well-known/jwks.json").Get().Handler(jwks).Context(ctrl),
		api.NewRoute("/swagger.{format}").Get().Handler(specGet).Context(ctrl),
	}
}
