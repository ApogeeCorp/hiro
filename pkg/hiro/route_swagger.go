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
	"context"
	"encoding/json"
	"net/http"

	"github.com/ModelRocket/hiro/api/swagger"
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ghodss/yaml"

	_ "embed"
)

type (
	// SpecGetInput is the input for spec get method
	SpecGetInput struct {
		Format string `json:"format"`
		Pretty bool   `json:"pretty"`
	}

	// SpecRoute is the swagger spec route handler
	SpecRoute func(ctx context.Context, params *SpecGetInput) api.Responder
)

func spec(ctx context.Context, params *SpecGetInput) api.Responder {
	var err error

	data := swagger.HiroSwaggerSpec

	switch params.Format {
	case "yaml":
		return api.NewResponse(data).
			WithWriter(api.Write).
			WithHeader("Content-Type", "text/yaml")

	case "json":
		data, err = yaml.YAMLToJSON(data)
		if err != nil {
			return api.Error(err)
		}

		if params.Pretty {
			var schemaObj map[string]interface{}

			if err := json.Unmarshal(data, &schemaObj); err != nil {
				return api.Error(err)
			}

			data, err = json.MarshalIndent(schemaObj, "", "  ")
			if err != nil {
				return api.Error(err)
			}
		}
		return api.NewResponse(data).
			WithWriter(api.Write).
			WithHeader("Content-Type", "application/json")

	default:
		return api.ErrNotFound
	}
}

// Name implements api.Route
func (SpecRoute) Name() string {
	return "spec"
}

// Methods implements api.Route
func (SpecRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (SpecRoute) Path() string {
	return "/swagger.{format}"
}
