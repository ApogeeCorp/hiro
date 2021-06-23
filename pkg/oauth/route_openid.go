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
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/ModelRocket/hiro/pkg/api"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"gopkg.in/square/go-jose.v2"
)

type (
	// OIDConfigInput is the input for the jwks route
	OIDConfigInput struct {
		Audience string `json:"audience"`
	}

	// OpenIDConfigRoute is the openid-configuration route
	OpenIDConfigRoute func(ctx context.Context, params *OIDConfigInput) api.Responder

	// JWKSInput is the input for the jwks route
	JWKSInput struct {
		Audience string `json:"audience"`
	}

	// JWKSRoute is the jwks route
	JWKSRoute func(ctx context.Context, params *JWKSInput) api.Responder
)

// Validate validates the JWKSInput struct
func (j JWKSInput) Validate() error {
	return validation.ValidateStruct(&j,
		validation.Field(&j.Audience, validation.Required))
}

func uriAppend(base string, paths ...string) string {
	v, _ := url.Parse(base)
	v.Path = path.Join(append([]string{path.Dir(v.Path)}, paths...)...)
	return v.String()
}

func openidConfig(ctx context.Context, params *OIDConfigInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	r, _ := api.Request(ctx)

	aud, err := ctrl.AudienceGet(ctx, AudienceGetInput{Audience: params.Audience})
	if err != nil {
		return ErrAudienceNotFound.WithError(err)
	}

	issuer := fmt.Sprintf("https://%s%s",
		r.Host,
		path.Clean(path.Join(path.Dir(r.URL.Path), "..")))

	config := struct {
		Issuer                 string      `json:"issuer"`
		JWKSURI                string      `json:"jwks_uri"`
		AuthorizationEndpoint  string      `json:"authorization_endpoint"`
		ResponseTypesSupported []string    `json:"response_type_supported"`
		SubjectTypesSupported  []string    `json:"subject_types_supported"`
		SigningAlgSupported    []string    `json:"id_token_signing_alg_values_supported"`
		TokenEndpoint          string      `json:"token_endpoint"`
		IntrospectionEndpoint  string      `json:"introspection_endpoint"`
		UserInfoEndpoint       string      `json:"userinfo_endpoint"`
		EndSessionEndpoint     string      `json:"end_session_endpoint"`
		RevocationEndpoint     string      `json:"revocation_endpoint"`
		GrantTypesSupported    []GrantType `json:"grant_types_supported"`
		ScopesSupported        Scope       `json:"scopes_supported"`
	}{
		Issuer:                 issuer,
		JWKSURI:                uriAppend(issuer, aud.ID(), ".well-known/jwks.json"),
		AuthorizationEndpoint:  uriAppend(issuer, "..", "authorize"),
		ResponseTypesSupported: []string{"code"},
		SubjectTypesSupported:  []string{"public"},
		SigningAlgSupported:    []string{"RS256", "HS256"},
		TokenEndpoint:          uriAppend(issuer, "..", "token"),
		IntrospectionEndpoint:  uriAppend(issuer, "..", "token-introspect"),
		UserInfoEndpoint:       uriAppend(issuer, "..", "userInfo"),
		EndSessionEndpoint:     uriAppend(issuer, "..", "logout"),
		RevocationEndpoint:     uriAppend(issuer, "..", "token-revoke"),
		GrantTypesSupported: []GrantType{
			GrantTypeAuthCode,
			GrantTypeClientCredentials,
			GrantTypeRefreshToken,
		},
		ScopesSupported: aud.Permissions(),
	}

	return api.NewResponse(config)
}

// Name implements api.Route
func (OpenIDConfigRoute) Name() string {
	return "openid-configuration"
}

// Methods implements api.Route
func (OpenIDConfigRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (OpenIDConfigRoute) Path() string {
	return "/openid/{audience_id}/.well-known/openid-configuration"
}

func jwks(ctx context.Context, params *JWKSInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	keys := make([]jose.JSONWebKey, 0)

	aud, err := ctrl.AudienceGet(ctx, AudienceGetInput{Audience: params.Audience})
	if err != nil {
		return ErrAudienceNotFound.WithError(err)
	}

	for _, s := range aud.Secrets() {
		if s.Algorithm() != TokenAlgorithmRS256 {
			return api.ErrBadRequest.WithMessage("audience does not support rsa tokens")
		}

		key := jose.JSONWebKey{
			KeyID:     s.ID(),
			Key:       &s.Key().(*rsa.PrivateKey).PublicKey,
			Algorithm: s.Algorithm().String(),
			Use:       "sig",
		}

		keys = append(keys, key)
	}

	return api.NewResponse(jose.JSONWebKeySet{
		Keys: keys,
	})
}

// Name implements api.Route
func (JWKSRoute) Name() string {
	return "openid-jwks"
}

// Methods implements api.Route
func (JWKSRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (JWKSRoute) Path() string {
	return "/openid/{audience_id}/.well-known/jwks.json"
}
