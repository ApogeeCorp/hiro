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
	"net/http"
	"net/url"
	"path"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/oauth/openid"
	"github.com/ModelRocket/hiro/pkg/ptr"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// VerifyParams are the params for user verify
	VerifyParams struct {
		RedirectURI string  `json:"redirect_uri"`
		State       *string `json:"state,omitempty"`
	}

	// VerifyRoute is the verify route
	VerifyRoute func(ctx context.Context, params *VerifyParams) api.Responder

	// VerifySendParams are the params for the verification send method
	VerifySendParams struct {
		Method NotificationChannel `json:"method"`
	}

	// VerifySendRoute is the verify send route
	VerifySendRoute func(ctx context.Context, params *VerifySendParams) api.Responder

	verifyNotification struct {
		audience string
		sub      string
		link     *string
		channel  NotificationChannel
	}

	// VerificationNotification is a user verification notification
	VerificationNotification interface {
		Notification
	}
)

// Validate validates the params
func (p VerifyParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.RedirectURI, validation.Required, is.RequestURI))
}

// Validate validates the params
func (p VerifySendParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Method, validation.Required))
}

func verify(ctx context.Context, params *VerifyParams) api.Responder {
	var token Token

	ctrl := api.Context(ctx).(Controller)

	api.RequirePrincipal(ctx, &token, api.PrincipalTypeUser)

	// we revoke verify tokens once they have been used
	ctrl.TokenRevoke(ctx, TokenRevokeInput{
		TokenID: &token.ID,
	})

	client, err := ctrl.ClientGet(ctx, ClientGetInput{
		Audience: token.Audience,
		ClientID: token.ClientID,
	})
	if err != nil {
		return api.ErrForbidden.WithError(err)
	}

	// validate the redirect uri
	rdrURI, err := EnsureURI(ctx, params.RedirectURI, client.RedirectEndpoints())
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	if token.Use != TokenUseVerify {
		return api.Redirect(rdrURI).WithError(ErrInvalidToken)
	}

	user, err := ctrl.UserGet(ctx, UserGetInput{
		Audience: token.Audience,
		Subject:  token.Subject,
	})
	if err != nil {
		return api.Redirect(rdrURI).WithError(err)
	}

	profile := user.Profile()

	if profile == nil {
		profile = &openid.Profile{}
	}

	if token.Scope.Contains(ScopeEmailVerify) {
		profile.EmailClaim = new(openid.EmailClaim)
		profile.EmailVerified = ptr.True
	}

	if token.Scope.Contains(ScopePhoneVerify) {
		profile.PhoneClaim = new(openid.PhoneClaim)
		profile.PhoneNumberVerified = ptr.True
	}

	if _, err := ctrl.UserUpdate(ctx, UserUpdateInput{
		Audience: token.Audience,
		Subject:  token.Subject,
		Profile:  profile,
	}); err != nil {
		return api.Redirect(rdrURI).WithError(err)
	}

	if params.State != nil {
		q := rdrURI.Query()
		q.Set("state", *params.State)
		rdrURI.RawQuery = q.Encode()
	}

	return api.Redirect(rdrURI).WithError(err)
}

// Name implements api.Route
func (VerifyRoute) Name() string {
	return "verify"
}

// Methods implements api.Route
func (VerifyRoute) Methods() []string {
	return []string{http.MethodGet}
}

// Path implements api.Route
func (VerifyRoute) Path() string {
	return "/verify"
}

// RequireAuth implements the api.AuthorizedRoute
func (VerifyRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (VerifyRoute) Scopes() ScopeList {
	return BuildScope(ScopeOpenID, ScopeProfile, ScopeEmailVerify)
}

func verifySend(ctx context.Context, params *VerifySendParams) api.Responder {
	var token Token
	scope := Scope{ScopeOpenID, ScopeProfile}

	ctrl := api.Context(ctx).(Controller)

	api.RequirePrincipal(ctx, &token, api.PrincipalTypeUser)

	r, _ := api.Request(ctx)

	switch params.Method {
	case NotificationChannelEmail:
		scope = append(scope, ScopeEmailVerify)
	case NotificationChannelPhone:
		scope = append(scope, ScopePhoneVerify)
	default:
		return api.ErrBadRequest.WithDetail("unsupported notification channel")
	}

	// revoke any existing verify tokens
	if err := ctrl.TokenRevoke(ctx, TokenRevokeInput{
		Subject:  token.Subject,
		TokenUse: TokenUseVerify.Ptr(),
	}); err != nil {
		return api.Error(err)
	}

	v, err := ctrl.TokenCreate(ctx, Token{
		Issuer:    issuer(ctx, token.Audience),
		Subject:   token.Subject,
		Audience:  token.Audience,
		ClientID:  token.ClientID,
		Use:       TokenUseVerify,
		Revokable: true,
		Scope:     scope,
	})
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	link, err := url.Parse(fmt.Sprintf("https://%s%s",
		r.Host,
		path.Clean(r.URL.Path)))
	if err != nil {
		return api.ErrServerError.WithError(err)
	}
	q := link.Query()
	q.Set("access_token", v.ID)
	link.RawQuery = q.Encode()

	if err := ctrl.UserNotify(ctx, &verifyNotification{
		audience: token.Audience,
		sub:      *token.Subject,
		channel:  params.Method,
		link:     ptr.String((link.String())),
	}); err != nil {
		return api.ErrServerError.WithError(err)
	}

	return api.NewResponse().WithStatus(http.StatusNoContent)
}

// Name implements api.Route
func (VerifySendRoute) Name() string {
	return "verify-send"
}

// Methods implements api.Route
func (VerifySendRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (VerifySendRoute) Path() string {
	return "/verify"
}

// RequireAuth implements the api.AuthorizedRoute
func (VerifySendRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (VerifySendRoute) Scopes() ScopeList {
	return BuildScope(ScopeOpenID, ScopeProfile)
}

func (n verifyNotification) Type() NotificationType {
	return NotificationTypeVerify
}

func (n verifyNotification) Audience() string {
	return n.audience
}

func (n verifyNotification) Subject() string {
	return n.sub
}

func (n verifyNotification) Context() map[string]interface{} {
	rval := make(map[string]interface{})

	if n.link != nil {
		rval["link"] = *n.link
	}

	return rval
}

func (n verifyNotification) Channels() []NotificationChannel {
	return []NotificationChannel{NotificationChannel(n.channel)}
}
