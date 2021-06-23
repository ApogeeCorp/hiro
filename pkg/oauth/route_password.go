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
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/ptr"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// PasswordCreateParams is the input to the password get route
	PasswordCreateParams struct {
		Login        string                `json:"login"`
		Notify       []NotificationChannel `json:"notify"`
		Type         PasswordType          `json:"type"`
		RequestToken string                `json:"request_token"`
		RedirectURI  string                `json:"redirect_uri"`
		CodeVerifier string                `json:"code_verifier"`
	}

	// PasswordCreateRoute is the password create handler
	PasswordCreateRoute func(ctx context.Context, params *PasswordCreateParams) api.Responder

	// PasswordUpdateParams are used by the password update route
	PasswordUpdateParams struct {
		Password    string  `json:"password"`
		ResetToken  string  `json:"reset_token"`
		RedirectURI *string `json:"redirect_uri,omitempty"`
	}

	// PasswordUpdateRoute is the password update handler
	PasswordUpdateRoute func(ctx context.Context, params *PasswordUpdateParams) api.Responder

	// PasswordType defines a password type
	PasswordType string

	// PasswordNotification is a password notification interface
	PasswordNotification interface {
		Notification
		PasswordType() PasswordType
		Code() string
	}

	passwordNotification struct {
		audience     string
		subject      string
		passwordType PasswordType
		link         *string
		code         string
		notify       []NotificationChannel
	}
)

const (
	// PasswordTypeLink is a magic password link
	PasswordTypeLink PasswordType = "link"

	// PasswordTypeCode is a one-time use password code
	PasswordTypeCode PasswordType = "code"

	// PasswordTypeReset sends both a link with the password scope and a code
	PasswordTypeReset PasswordType = "reset"
)

var (
	passcodeAlpha = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}
)

// Validate validates the PasswordType
func (p PasswordType) Validate() error {
	return validation.Validate(string(p), validation.In("link", "code", "reset"))
}

// Validate validates PasswordGetInput
func (p PasswordCreateParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Login, validation.Required),
		validation.Field(&p.Type, validation.Required),
		validation.Field(&p.Notify, validation.Required, validation.Each(validation.In(NotificationChannelEmail, NotificationChannelPhone))),
		validation.Field(&p.RequestToken, validation.Required),
		validation.Field(&p.RedirectURI, validation.Required, is.RequestURI),
		validation.Field(&p.CodeVerifier, validation.Required),
	)
}

// Validate validates PasswordGetInput
func (p PasswordUpdateParams) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Password, validation.Required),
		validation.Field(&p.ResetToken, validation.Required),
		validation.Field(&p.RedirectURI, validation.NilOrNotEmpty, is.RequestURI),
	)
}

func passwordCreate(ctx context.Context, params *PasswordCreateParams) api.Responder {
	ctrl := api.Context(ctx).(Controller)

	req, err := ctrl.RequestTokenGet(ctx, RequestTokenGetInput{
		TokenID:   params.RequestToken,
		TokenType: RequestTokenTypePtr(RequestTokenTypeLogin),
	})
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	// errors will be redirect back to the app endpoint of the original request
	appURI, err := url.Parse(*req.AppURI)
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	if req.Expired() {
		return api.Redirect(appURI).WithError(ErrExpiredToken)
	}

	if err := req.CodeChallenge.Verify(params.CodeVerifier); err != nil {
		return api.Redirect(appURI).WithError(ErrUnauthorized.WithError(err))
	}

	// validate the redirect uri
	client, err := ctrl.ClientGet(ctx, ClientGetInput{
		Audience: req.Audience,
		ClientID: req.ClientID,
	})
	if err != nil {
		return api.Redirect(appURI).WithError(ErrForbidden.WithError(err))
	}

	rdrURI, err := EnsureURI(ctx, params.RedirectURI, client.RedirectEndpoints())
	if err != nil {
		return api.Redirect(appURI).WithError(ErrForbidden)
	}

	user, err := ctrl.UserGet(ctx, UserGetInput{
		Audience: req.Audience,
		Login:    &params.Login,
	})
	if err != nil {
		return api.Redirect(appURI).WithError(ErrUnauthorized.WithError(err))
	}

	req.Subject = ptr.String(user.ID())

	// The new token is for sessions which should be one time use
	req.Type = RequestTokenTypeSession

	if params.Type == PasswordTypeCode {
		// generate a simple OTP for the this request
		req.Passcode = ptr.String(generatePasscode(PasscodeLength))

	} else if params.Type == PasswordTypeReset {
		// the user will need the password reset scope for thier magic link token
		req.Scope = append(req.Scope, ScopePassword)

		// create a password reset token that the user will use to change their password
		passToken, err := ctrl.RequestTokenCreate(ctx, RequestToken{
			Type:     RequestTokenTypeVerify,
			Subject:  req.Subject,
			ClientID: req.ClientID,
			Audience: req.Audience,
		})
		if err != nil {
			return api.Redirect(appURI).WithError(ErrUnauthorized.WithError(err))
		}

		req.Passcode = &passToken
	}

	reqToken, err := ctrl.RequestTokenCreate(ctx, req)
	if err != nil {
		return api.Redirect(appURI).WithError(ErrUnauthorized.WithError(err))
	}

	note := &passwordNotification{
		audience:     req.Audience,
		subject:      user.ID(),
		passwordType: params.Type,
		notify:       params.Notify,
		code:         *req.Passcode,
	}

	if params.Type.IsLink() {
		// link and resets need a magic session link with an access token
		r, _ := api.Request(ctx)

		token, err := ctrl.TokenCreate(ctx, Token{
			Issuer:    issuer(ctx, req.Audience),
			Subject:   ptr.String(user.ID()),
			Audience:  req.Audience,
			ClientID:  req.ClientID,
			Use:       TokenUseAccess,
			Revokable: true,
			Scope:     Scope{ScopeSession},
		})
		if err != nil {
			return api.Redirect(appURI).WithError(ErrUnauthorized.WithError(err))
		}

		link, err := url.Parse(
			fmt.Sprintf("https://%s%s",
				r.Host,
				path.Clean(path.Join(path.Dir(r.URL.Path), "session"))))
		if err != nil {
			return api.Redirect(appURI).WithError(ErrUnauthorized.WithError(err))
		}

		q := link.Query()
		q.Set("access_token", token.ID)
		q.Set("request_token", reqToken)

		link.RawQuery = q.Encode()

		note.link = ptr.String(link.String())
	}

	if err := ctrl.UserNotify(ctx, note); err != nil {
		return api.Redirect(appURI).WithError(ErrUnauthorized.WithError(err))
	}

	q := rdrURI.Query()
	if !params.Type.IsLink() {
		q.Set("request_token", reqToken)
	}
	if req.State != nil {
		q.Set("state", *req.State)
	}

	rdrURI.RawQuery = q.Encode()

	return api.Redirect(rdrURI)
}

// Name implements api.Route
func (PasswordCreateRoute) Name() string {
	return "passwordCreate"
}

// Methods implements api.Route
func (PasswordCreateRoute) Methods() []string {
	return []string{http.MethodPost}
}

// Path implements api.Route
func (PasswordCreateRoute) Path() string {
	return "/password"
}

func passwordUpdate(ctx context.Context, params *PasswordUpdateParams) api.Responder {
	var token Token

	ctrl := api.Context(ctx).(Controller)

	api.RequirePrincipal(ctx, &token, api.PrincipalTypeUser)

	req, err := ctrl.RequestTokenGet(ctx, RequestTokenGetInput{
		TokenID:   params.ResetToken,
		TokenType: RequestTokenTypePtr(RequestTokenTypeVerify),
	})
	if err != nil {
		return ErrUnauthorized.WithError(err)
	}

	var u *url.URL

	if params.RedirectURI != nil {
		client, err := ctrl.ClientGet(ctx, ClientGetInput{
			Audience: token.Audience,
			ClientID: token.ClientID,
		})
		if err != nil {
			return ErrUnauthorized.WithError(err)
		}

		u, err = EnsureURI(ctx, *params.RedirectURI, client.RedirectEndpoints())
		if err != nil {
			return ErrUnauthorized.WithError(err)
		}
	}

	if req.Expired() {
		return api.RedirectErrIf(u != nil, u, ErrExpiredToken)
	}

	if *req.Subject != *token.Subject {
		return api.RedirectErrIf(u != nil, u, ErrUnauthorized.WithDetail("subject does not match"))
	}

	if _, err := ctrl.UserUpdate(ctx, UserUpdateInput{
		Audience: token.Audience,
		Subject:  token.Subject,
		Password: &params.Password,
	}); err != nil {
		return api.RedirectErrIf(u != nil, u, err)
	}

	return api.RedirectIf(u != nil, u)
}

// Name implements api.Route
func (PasswordUpdateRoute) Name() string {
	return "password-update"
}

// Methods implements api.Route
func (PasswordUpdateRoute) Methods() []string {
	return []string{http.MethodPut}
}

// Path implements api.Route
func (PasswordUpdateRoute) Path() string {
	return "/password"
}

// RequireAuth implements the api.AuthorizedRoute
func (PasswordUpdateRoute) RequireAuth() []api.CredentialType {
	return []api.CredentialType{api.CredentialTypeBearer}
}

// Scopes implements oauth.Route
func (PasswordUpdateRoute) Scopes() ScopeList {
	return BuildScope(ScopePassword)
}

func (n passwordNotification) Type() NotificationType {
	return NotificationTypePassword
}

func (n passwordNotification) Audience() string {
	return n.audience
}

func (n passwordNotification) Subject() string {
	return n.subject
}

func (n passwordNotification) Context() map[string]interface{} {
	rval := make(map[string]interface{})

	if n.link != nil {
		rval["link"] = *n.link
	}

	return rval
}

func (n passwordNotification) PasswordType() PasswordType {
	return n.passwordType
}

func (n passwordNotification) Code() string {
	return n.code
}

func (n passwordNotification) Channels() []NotificationChannel {
	return n.notify
}

// IsLink returns true if its a link type
func (p PasswordType) IsLink() bool {
	return p == PasswordTypeLink || p == PasswordTypeReset
}

func (p PasswordType) String() string {
	return string(p)
}

func generatePasscode(max int) string {
	b := make([]byte, max)
	n, err := io.ReadAtLeast(rand.Reader, b, max)
	if n != max {
		panic(err)
	}
	for i := 0; i < len(b); i++ {
		b[i] = passcodeAlpha[int(b[i])%len(passcodeAlpha)]
	}
	return string(b)
}
