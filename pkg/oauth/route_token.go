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
	"math/rand"
	"net/http"
	"path"
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/ModelRocket/hiro/pkg/types"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

func init() {
	rand.Seed(time.Now().Unix())
}

type (
	// TokenIntrospectParams is the parameters for token introspect
	TokenIntrospectParams struct {
		Token string `json:"token"`
	}

	// TokenIntrospectRoute is the openid token introspection route
	TokenIntrospectRoute func(ctx context.Context, params *TokenIntrospectParams) api.Responder

	// TokenRevokeParams is the parameters for token revoke
	TokenRevokeParams struct {
		Token string `json:"token"`
	}

	// TokenRevokeRoute is the openid token revoke route
	TokenRevokeRoute func(ctx context.Context, params *TokenRevokeParams) api.Responder

	// TokenParams is the parameters for the token request
	TokenParams struct {
		ClientID     string    `json:"client_id"`
		ClientSecret *string   `json:"client_secret"`
		GrantType    GrantType `json:"grant_type"`
		Code         *string   `json:"code,omitempty"`
		RedirectURI  *URI      `json:"redirect_uri,omitempty"`
		CodeVerifier *string   `json:"code_verifier,omitempty"`
	}

	// TokenRoute is the token route
	TokenRoute func(ctx context.Context, params *TokenParams) api.Responder
)

// Validate handles the validation for the TokenParams struct
func (p TokenIntrospectParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Token, validation.Required),
	)
}

// Validate handles the validation for the TokenParams struct
func (p TokenRevokeParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Token, validation.Required),
	)
}

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

	log := api.Log(ctx).WithField("operation", "token")

	client, err := ctrl.ClientGet(ctx, params.ClientID, safe.String(params.ClientSecret))
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	r, _ := api.Request(ctx)

	switch params.GrantType {
	case GrantTypeAuthCode:
		req, err := ctrl.RequestTokenGet(ctx, *params.Code, RequestTokenTypeAuthCode)
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

		aud, err := ctrl.AudienceGet(ctx, req.Audience)
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}

		issuer := URI(
			fmt.Sprintf("https://%s%s",
				r.Host,
				path.Clean(path.Join(path.Dir(r.URL.Path), "openid", aud.ID()))),
		)

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

		log.Debugf("access token %s issued", access.ID)

		tokens = append(tokens, access)

		if req.Scope.Contains(ScopeOpenID) {
			id, err := ctrl.TokenCreate(ctx, Token{
				Issuer:   &issuer,
				Subject:  &req.Subject,
				Audience: req.Audience,
				ClientID: req.ClientID,
				Use:      TokenUseIdentity,
				AuthTime: &req.CreatedAt,
			})
			if err != nil {
				return ErrAccessDenied.WithError(err)
			}

			user, err := ctrl.UserGet(ctx, req.Subject)
			if err != nil {
				return ErrAccessDenied.WithError(err)
			}

			if user.Profile() != nil {
				if req.Scope.Contains(ScopeProfile) {
					profile := make(Claims)
					profile.Encode(user.Profile())

					// the profile claim does not include these
					profile.Delete(
						"address",
						"email",
						"email_verified",
						"phone_number",
						"phone_number_verified")

					id.Claims.Merge(profile)
				}
				if req.Scope.Contains(ScopeAddress) {
					address := make(Claims)
					address.Encode(user.Profile().Address)

					id.Claims.Set("address", address)
				}
				if req.Scope.Contains(ScopePhone) {
					phone := make(Claims)
					phone.Encode(user.Profile().PhoneClaim)

					id.Claims.Merge(phone)
				}
				if req.Scope.Contains(ScopeEmail) {
					email := make(Claims)
					email.Encode(user.Profile().EmailClaim)

					id.Claims.Merge(email)
				}
			}

			log.Debugf("identity token %s issued", id.ID)

			tokens = append(tokens, id)
		}

		secrets := aud.Secrets()
		if len(secrets) == 0 {
			return ErrKeyNotFound
		}

		bearer, err = NewBearer(secrets[rand.Intn(len(secrets))], tokens...)
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}
	}

	return api.NewResponse(bearer).
		WithHeader("Cache-Control", "no-store").
		WithHeader("Pragma", "no-cache")
}

// Name implements api.Route
func (TokenRoute) Name() string {
	return "token"
}

// Methods implements api.Route
func (TokenRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (TokenRoute) Path() string {
	return "/token"
}

// Handler implements api.Route
func (r TokenRoute) Handler() interface{} {
	return r
}

// ValidateParameters implements api.Route
func (TokenRoute) ValidateParameters() bool {
	return true
}

// RequireAuth implements api.Route
func (TokenRoute) RequireAuth() bool {
	return false
}

func tokenIntrospect(ctx context.Context, params *TokenIntrospectParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	if len(params.Token) == 22 {
		token, err := ctrl.TokenGet(ctx, params.Token)
		if err != nil {
			return api.Error(err)
		}

		if token.ExpiresAt.Time().After(time.Now()) {
			token.Claims["active"] = true
		}

		return api.NewResponse(token)
	}

	var token Token

	api.RequirePrincipal(ctx, &token)

	t, err := ParseBearer(params.Token, func(kid string, c Claims) (TokenSecret, error) {
		aud, err := ctrl.AudienceGet(ctx, c.Audience())
		if err != nil {
			return nil, err
		}

		for _, s := range aud.Secrets() {
			if string(s.ID()) == kid {
				return s, nil
			}
		}

		return nil, ErrKeyNotFound
	})
	if err != nil {
		return api.Error(err)
	}

	if t.ExpiresAt.Time().After(time.Now()) {
		t.Claims["active"] = true
	}

	return api.NewResponse(t)
}

// Name implements api.Route
func (TokenIntrospectRoute) Name() string {
	return "token-introspect"
}

// Methods implements api.Route
func (TokenIntrospectRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (TokenIntrospectRoute) Path() string {
	return "/token-introspect"
}

// Handler implements api.Route
func (r TokenIntrospectRoute) Handler() interface{} {
	return r
}

// ValidateParameters implements api.Route
func (TokenIntrospectRoute) ValidateParameters() bool {
	return true
}

// RequireAuth implements api.Route
func (TokenIntrospectRoute) RequireAuth() bool {
	return true
}

// Scopes implements oauth.Route
func (TokenIntrospectRoute) Scopes() []Scope {
	return []Scope{MakeScope(ScopeTokenRead)}
}

func tokenRevoke(ctx context.Context, params *TokenRevokeParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	if len(params.Token) == 22 {
		if err := ctrl.TokenRevoke(ctx, types.ID(params.Token)); err != nil {
			return api.Error(err)
		}

		return api.NewResponse().WithStatus(http.StatusNoContent)
	}

	return ErrInvalidToken.WithDetail("token not revokable")
}

// Name implements api.Route
func (TokenRevokeRoute) Name() string {
	return "token-revoke"
}

// Methods implements api.Route
func (TokenRevokeRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (TokenRevokeRoute) Path() string {
	return "/token-revoke"
}

// Handler implements api.Route
func (r TokenRevokeRoute) Handler() interface{} {
	return r
}

// ValidateParameters implements api.Route
func (TokenRevokeRoute) ValidateParameters() bool {
	return true
}

// RequireAuth implements api.Route
func (TokenRevokeRoute) RequireAuth() bool {
	return true
}

// Scopes implements oauth.Route
func (TokenRevokeRoute) Scopes() []Scope {
	return []Scope{MakeScope(ScopeTokenRevoke)}
}
