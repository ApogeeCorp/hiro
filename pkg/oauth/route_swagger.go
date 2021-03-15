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
	"encoding/json"
	"net/http"

	"github.com/ModelRocket/hiro/api/swagger"
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ghodss/yaml"
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

	data := swagger.OauthSwaggerSpec

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
