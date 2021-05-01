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
	"fmt"
	"math/rand"
	"net/http"
	"path"
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/safe"
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
		Audience     *string   `json:"audience,omitempty"`
		ClientSecret *string   `json:"client_secret"`
		GrantType    GrantType `json:"grant_type"`
		Code         *string   `json:"code,omitempty"`
		RefreshToken *string   `json:"refresh_token,omitempty"`
		Scope        Scope     `json:"scope,omitempty"`
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
		validation.Field(&p.ClientSecret, validation.When(p.GrantType == GrantTypeClientCredentials, validation.Required).Else(validation.Nil)),
		validation.Field(&p.Audience, validation.When(p.GrantType == GrantTypeClientCredentials, validation.Required).Else(validation.Nil)),
		validation.Field(&p.RedirectURI, validation.When(p.GrantType == GrantTypeAuthCode, validation.Required).Else(validation.Nil)),
		validation.Field(&p.Code, validation.When(p.GrantType == GrantTypeAuthCode, validation.Required).Else(validation.Nil)),
		validation.Field(&p.RefreshToken, validation.When(p.GrantType == GrantTypeRefreshToken, validation.Required).Else(validation.Nil)),
		validation.Field(&p.CodeVerifier, validation.When(p.GrantType == GrantTypeAuthCode, validation.Required).Else(validation.NilOrNotEmpty)),
		validation.Field(&p.GrantType, validation.Required, validation.In(
			GrantTypeClientCredentials,
			GrantTypeAuthCode,
			GrantTypeRefreshToken,
			GrantTypePassword)),
	)
}

func issuer(ctx context.Context, aud string) *URI {
	r, _ := api.Request(ctx)

	iss := URI(
		fmt.Sprintf("https://%s%s",
			r.Host,
			path.Clean(path.Join(path.Dir(r.URL.Path), "openid", aud))),
	)

	return &iss
}

func token(ctx context.Context, params *TokenParams) api.Responder {
	var bearer *BearerToken
	var aud Audience
	var refreshToken *string
	var req RequestToken
	var err error

	tokens := make([]Token, 0)

	ctrl := api.Context(ctx).(Controller)

	log := api.Log(ctx).WithField("operation", "token").WithField("grant_type", params.GrantType)

	client, err := ctrl.ClientGet(ctx, params.ClientID, safe.String(params.ClientSecret))
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}

	switch params.GrantType {
	case GrantTypeClientCredentials:
		aud, err = ctrl.AudienceGet(ctx, *params.Audience)
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}

		if err := client.Authorize(ctx, aud, params.GrantType, []URI{}, params.Scope); err != nil {
			return ErrAccessDenied.WithError(err)
		}

		access, err := ctrl.TokenCreate(ctx, Token{
			Issuer:   issuer(ctx, aud.ID()),
			Audience: *params.Audience,
			ClientID: params.ClientID,
			Use:      TokenUseAccess,
			Scope:    params.Scope,
		})
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}

		log.Debugf("access token %s issued", access.ID)

		tokens = append(tokens, access)

		if params.Scope.Contains(ScopeOfflineAccess) {
			rt, err := ctrl.RequestTokenCreate(ctx, RequestToken{
				Type:                RequestTokenTypeRefreshToken,
				Audience:            *params.Audience,
				ClientID:            params.ClientID,
				ExpiresAt:           Time(time.Now().Add(aud.RefreshTokenLifetime())),
				Scope:               params.Scope,
				CodeChallengeMethod: PKCEChallengeMethodNone,
			})
			if err != nil {
				return ErrAccessDenied.WithError(err)
			}

			refreshToken = &rt
		}

	case GrantTypeRefreshToken:
		req, err = ctrl.RequestTokenGet(ctx, *params.RefreshToken, RequestTokenTypeRefreshToken)
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}
		fallthrough

	case GrantTypeAuthCode:
		if req.Type != RequestTokenTypeRefreshToken {
			req, err = ctrl.RequestTokenGet(ctx, *params.Code, RequestTokenTypeAuthCode)
			if err != nil {
				return ErrAccessDenied.WithError(err)
			}
		}

		if req.CodeChallengeMethod == PKCEChallengeMethodS256 {
			if err := req.CodeChallenge.Verify(*params.CodeVerifier); err != nil {
				return ErrAccessDenied.WithError(err)
			}
		}

		if req.RedirectURI != nil {
			if params.RedirectURI == nil || *params.RedirectURI != *req.RedirectURI {
				return ErrAccessDenied.WithDetail("redirect_uri mismatch")
			}
		}

		if req.ClientID != client.ClientID() {
			return ErrAccessDenied.WithDetail("client_id mismatch")
		}

		aud, err = ctrl.AudienceGet(ctx, req.Audience)
		if err != nil {
			return ErrAccessDenied.WithError(err)
		}

		access, err := ctrl.TokenCreate(ctx, Token{
			Issuer:   issuer(ctx, aud.ID()),
			Subject:  req.Subject,
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

		if req.Scope.Contains(ScopeOpenID) && req.Subject != nil {
			id, err := ctrl.TokenCreate(ctx, Token{
				Issuer:   issuer(ctx, aud.ID()),
				Subject:  req.Subject,
				Audience: req.Audience,
				ClientID: req.ClientID,
				Use:      TokenUseIdentity,
				AuthTime: &req.CreatedAt,
			})
			if err != nil {
				return ErrAccessDenied.WithError(err)
			}

			user, err := ctrl.UserGet(ctx, safe.String(req.Subject))
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

		if req.Scope.Contains(ScopeOfflineAccess) {
			// convert the request to a refresh token
			if req.Type != RequestTokenTypeRefreshToken {
				// existing tokens should have the same expiration
				req.ExpiresAt = Time(time.Now().Add(aud.RefreshTokenLifetime()))
			}
			req.Type = RequestTokenTypeRefreshToken
			req.RedirectURI = nil
			req.AppURI = nil

			rt, err := ctrl.RequestTokenCreate(ctx, req)
			if err != nil {
				return ErrAccessDenied.WithError(err)
			}

			refreshToken = &rt
		}
	}

	secrets := aud.Secrets()
	if len(secrets) == 0 {
		return ErrKeyNotFound
	}

	bearer, err = NewBearer(secrets[rand.Intn(len(secrets))], tokens...)
	if err != nil {
		return ErrAccessDenied.WithError(err)
	}
	bearer.RefreshToken = refreshToken

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

// RequireAuth implements the api.AuthorizedRoute
func (TokenIntrospectRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (TokenIntrospectRoute) Scopes() ScopeList {
	return BuildScope(ScopeTokenRead)
}

func tokenRevoke(ctx context.Context, params *TokenRevokeParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	if len(params.Token) == 22 {
		if err := ctrl.TokenRevoke(ctx, params.Token); err != nil {
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

// RequireAuth implements the api.AuthorizedRoute
func (TokenRevokeRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (TokenRevokeRoute) Scopes() ScopeList {
	return BuildScope(ScopeTokenRevoke)
}
