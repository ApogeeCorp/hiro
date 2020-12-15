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
	"fmt"
	"path"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/ModelRocket/hiro/pkg/types"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// TokenParams is the parameters for the token request
	TokenParams struct {
		ClientID     types.ID  `json:"client_id"`
		ClientSecret *string   `json:"client_secret"`
		GrantType    GrantType `json:"grant_type"`
		Code         *string   `json:"code,omitempty"`
		RedirectURI  *URI      `json:"redirect_uri,omitempty"`
		CodeVerifier *string   `json:"code_verifier,omitempty"`
	}
)

// Validate handles the validation for the TokenParams struct
func (p TokenParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.ClientID, validation.Required),
		validation.Field(&p.RedirectURI, validation.When(p.GrantType == GrantTypeAuthCode, validation.Required).Else(validation.Nil)),
		validation.Field(&p.Code, validation.When(p.GrantType == GrantTypeAuthCode, validation.Required).Else(validation.Nil)),
		validation.Field(&p.CodeVerifier, validation.When(p.GrantType == GrantTypeAuthCode, validation.Required).Else(validation.Nil)),
		validation.Field(&p.GrantType, validation.Required, validation.In(GrantTypeAuthCode)),
	)
}

func token(ctx context.Context, params *TokenParams) api.Responder {
	var bearer *BearerToken

	ctrl := api.Context(ctx).(Controller)

	//log := api.Log(ctx).WithField("operation", "token")

	client, err := ctrl.ClientGet(ctx, params.ClientID, safe.String(params.ClientSecret))
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	r, _ := api.Request(ctx)

	switch params.GrantType {
	case GrantTypeAuthCode:
		req, err := ctrl.RequestTokenGet(ctx, *params.Code)
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}

		if req.RedirectURI != nil {
			if params.RedirectURI == nil || *params.RedirectURI != *req.RedirectURI {
				return ErrAccessDenied.WithDetail("redirect_uri mismatch")
			}
		}

		if req.ClientID != client.ClientID() {
			return ErrAccessDenied.WithDetail("client_id mismatch")
		}

		aud, err := ctrl.AudienceGet(ctx, req.Audience.String())
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}

		issuer := URI(
			fmt.Sprintf("https://%s%s?audience=%s",
				r.Host,
				path.Clean(path.Join(path.Dir(r.URL.Path), "/.well-known/jwks.json")),
				aud.ID()))

		tokens := make([]Token, 0)

		access, err := ctrl.TokenCreate(ctx, Token{
			Issuer:   &issuer,
			Subject:  &req.Subject,
			Audience: req.Audience,
			ClientID: req.ClientID,
			Use:      TokenUseAccess,
			Scope:    req.Scope,
		})
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}
		tokens = append(tokens, access)

		if req.Scope.Contains(ScopeOpenID) {
			id, err := ctrl.TokenCreate(ctx, Token{
				Issuer:   &issuer,
				Subject:  &req.Subject,
				Audience: req.Audience,
				ClientID: req.ClientID,
				Use:      TokenUseIdentity,
				Scope:    req.Scope,
				AuthTime: &req.CreatedAt,
			})
			if err != nil {
				return ErrAccessDenied.WithError(err)
			}
			tokens = append(tokens, id)
		}

		bearer, err = NewBearer(aud.Secret(), tokens...)
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}
	}

	return api.NewResponse(bearer).
		WithHeader("Cache-Control", "no-store").
		WithHeader("Pragma", "no-cache")
}
