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

// Package oauth provides the base auth interfaces
package oauth

import "github.com/ModelRocket/hiro/api/spec"

var (
	// Scopes is the spec defined oauth 2.0 scopes
	Scopes = make([]string, 0)
)

func init() {
	for key, def := range spec.SpecDoc.Spec().SecurityDefinitions {
		if def.Type != "oauth2" || key != "OAuth" {
			continue
		}

		for scope := range def.Scopes {
			Scopes = append(Scopes, scope)
		}
	}
}
