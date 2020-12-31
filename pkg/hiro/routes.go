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

import "github.com/ModelRocket/sparks/pkg/api"

// Routes returns the oauth api routes
func Routes() []api.Route {
	return []api.Route{
		AudienceCreateRoute(audienceCreate),
		AudienceGetRoute(audienceGet),
		AudienceCountRoute(audienceCount),
		AudienceListRoute(audienceList),
		AudienceUpdateRoute(audienceUpdate),
		AudienceDeleteRoute(audienceDelete),
		ApplicationCreateRoute(applicationCreate),
		ApplicationGetRoute(applicationGet),
		ApplicationCountRoute(applicationCount),
		ApplicationListRoute(applicationList),
		ApplicationUpdateRoute(applicationUpdate),
		ApplicationDeleteRoute(applicationDelete),
		UserCreateRoute(userCreate),
		UserGetRoute(userGet),
		UserCountRoute(userCount),
		UserListRoute(userList),
		UserDeleteRoute(userDelete),
		SpecRoute(spec),
	}
}
