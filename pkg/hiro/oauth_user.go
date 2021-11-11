/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://githuh.com/ModelRocket/hiro
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

package hiro

import (
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/oauth/openid"
)

type (
	oauthUser struct {
		*User
		inst *Instance
	}
)

func (u oauthUser) ID() string {
	return u.User.ID.String()
}

func (u oauthUser) Audience() string {
	return ""
}

func (u oauthUser) Permissions() oauth.Scope {
	rval := make(oauth.Scope, 0)

	for _, r := range u.Roles {
		for _, p := range r.Permissions {
			rval = append(rval, p.Scope)
		}
	}

	return rval.Unique()
}

func (u oauthUser) Profile() *openid.Profile {
	return u.User.Profile
}
