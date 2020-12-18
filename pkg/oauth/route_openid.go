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
	"context"
	"crypto/rsa"
	"fmt"
	"path"

	"github.com/ModelRocket/hiro/pkg/api"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"gopkg.in/square/go-jose.v2"
)

type (
	// OIDConfigInput is the input for the jwks route
	OIDConfigInput struct {
		Audience string `json:"audience_id"`
	}

	// JWKSInput is the input for the jwks route
	JWKSInput struct {
		Audience string `json:"audience_id"`
	}
)

// Validate validates the JWKSInput struct
func (j JWKSInput) Validate() error {
	return validation.ValidateStruct(&j,
		validation.Field(&j.Audience, validation.Required))
}

func openidConfig(ctx context.Context, params *OIDConfigInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	r, _ := api.Request(ctx)

	aud, err := ctrl.AudienceGet(ctx, params.Audience)
	if err != nil {
		return ErrAudienceNotFound.WithError(err)
	}

	issuer := URI(
		fmt.Sprintf("https://%s%s",
			r.Host,
			path.Clean(path.Join(path.Dir(r.URL.Path), ".."))),
	)

	config := struct {
		Issuer                 URI         `json:"issuer"`
		JWKSURI                URI         `json:"jwks_uri"`
		AuthorizationEndpoint  URI         `json:"authorization_endpoint"`
		ResponseTypesSupported []string    `json:"response_type_supported"`
		SubjectTypesSupported  []string    `json:"subject_types_supported"`
		SigningAlgSupported    []string    `json:"id_token_signing_alg_values_supported"`
		TokenEndpoint          URI         `json:"token_endpoint"`
		IntrospectionEndpoint  URI         `json:"introspection_endpoint"`
		UserInfoEndpoint       URI         `json:"userinfo_endpoint"`
		RevocationEndpoint     URI         `json:"revocation_endpoint"`
		GrantTypesSupported    []GrantType `json:"grant_types_supported"`
		ScopesSupported        Scope       `json:"scopes_supported"`
	}{
		Issuer:                 issuer,
		JWKSURI:                issuer.Append(aud.ID().String(), ".well-known/jwks.json"),
		AuthorizationEndpoint:  issuer.Append("..", "authorize"),
		ResponseTypesSupported: []string{"code"},
		SubjectTypesSupported:  []string{"public"},
		SigningAlgSupported:    []string{"RS256", "HS256"},
		TokenEndpoint:          issuer.Append("..", "token"),
		IntrospectionEndpoint:  issuer.Append("..", "userInfo"),
		UserInfoEndpoint:       issuer.Append("..", "userInfo"),
		RevocationEndpoint:     issuer.Append("..", "revoke"),
		GrantTypesSupported:    []GrantType{GrantTypeAuthCode, GrantTypeClientCredentials, GrantTypeRefreshToken},
		ScopesSupported:        aud.Permissions(),
	}

	return api.NewResponse(config)
}

func jwks(ctx context.Context, params *JWKSInput) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	keys := make([]jose.JSONWebKey, 0)

	aud, err := ctrl.AudienceGet(ctx, params.Audience)
	if err != nil {
		return ErrAudienceNotFound.WithError(err)
	}

	if aud.Secret().Algorithm != TokenAlgorithmRS256 {
		return api.ErrBadRequest.WithMessage("audience does not support rsa tokens")
	}

	key := jose.JSONWebKey{
		KeyID:     aud.ID().String(),
		Key:       &aud.Secret().key.(*rsa.PrivateKey).PublicKey,
		Algorithm: aud.Secret().Algorithm.String(),
		Use:       "sig",
	}

	keys = append(keys, key)

	return api.NewResponse(jose.JSONWebKeySet{
		Keys: keys,
	})
}
