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
		api.NewRoute("/authorize").Get().Handler(authorize).Context(ctrl).Validate(),
		api.NewRoute("/login").Post().Handler(login).Context(ctrl).Validate(),
		api.NewRoute("/logout").Get().Handler(logout).Context(ctrl).Validate(),
		api.NewRoute("/session").Get().Handler(session).Context(ctrl).Validate().Authorizers(auth.AuthorizeScope(ScopeSession)),
		api.NewRoute("/signup").Post().Handler(signup).Context(ctrl).Validate(),
		api.NewRoute("/token").Post().Handler(token).Context(ctrl).Validate(),
		api.NewRoute("/verify").Get().Handler(verify).Context(ctrl).Validate().Authorizers(auth.AuthorizeScope(ScopeOpenID, ScopeProfile)),
		api.NewRoute("/verify").Post().Handler(verifySend).Context(ctrl).Validate().Authorizers(auth.AuthorizeScope(ScopeOpenID, ScopeProfile)),
		api.NewRoute("/password").Post().Handler(passwordCreate).Context(ctrl).Validate(),
		api.NewRoute("/password").Put().Handler(passwordUpdate).Context(ctrl).Validate().Authorizers(auth.AuthorizeScope(ScopePassword)),
		api.NewRoute("/userinfo").Get().Handler(userinfo).Context(ctrl).Validate().Authorizers(auth.AuthorizeScope(ScopeOpenID, ScopeProfile)),
		api.NewRoute("/userinfo").Patch().Handler(userinfoUpdate).Context(ctrl).Validate().Authorizers(auth.AuthorizeScope(ScopeOpenID, ScopeProfile)),
		api.NewRoute("/openid/{audience_id}/.well-known/openid-configuration").Get().Handler(openidConfig).Context(ctrl).Validate(),
		api.NewRoute("/openid/{audience_id}/.well-known/jwks.json").Get().Handler(jwks).Context(ctrl).Validate(),
		api.NewRoute("/swagger.{format}").Get().Handler(specGet).Context(ctrl).Validate(),
	}
}
