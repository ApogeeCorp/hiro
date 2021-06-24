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
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// Client is an oauth client interface
	Client interface {
		Principal

		// Type returns the client type
		Type() ClientType

		// TokenSecret returns the client token secret
		TokenSecret() TokenSecret

		// AuthorizedGrants returns the grants this client is authorized to use
		AuthorizedGrants() GrantList

		// ApplicationEndpoints are uris that can be used as valid application flow redirects
		ApplicationEndpoints() []string

		// RedirectEndpoints are uris that can be used as valid authorization flow redirects
		RedirectEndpoints() []string
	}

	// ClientType is an oauth client type
	ClientType string

	AuthorizeClientInput struct {
		GrantType   GrantType
		AppURI      *string
		RedirectURI *string
		Scope       Scope
		Request     *http.Request
	}
)

const (
	// ClientTypeWeb defines a web based client type
	// 	Web based clients are restricted from passing client_secret values
	// 	and using password grants
	ClientTypeWeb ClientType = "web"

	// ClientTypeNative defines a native application client type
	ClientTypeNative ClientType = "native"

	// ClientTypeMachine defines a machine to machine client type
	ClientTypeMachine ClientType = "machine"
)

// Validate handles validation for ClientType
func (c ClientType) Validate() error {
	return validation.Validate(string(c), validation.In("web", "native", "machine"))
}
