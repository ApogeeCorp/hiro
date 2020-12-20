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
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/oauth/openid"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/ModelRocket/hiro/pkg/types"
	"github.com/apex/log"
)

type (
	oauthController struct {
		*Backend
	}

	oauthAudience struct {
		*Audience
	}

	oauthClient struct {
		*Application
	}

	oauthUser struct {
		*User
	}

	requestToken struct {
		ID                  types.ID                  `db:"id"`
		Type                oauth.RequestTokenType    `db:"type"`
		CreatedAt           oauth.Time                `db:"created_at"`
		Audience            types.ID                  `db:"audience_id"`
		ApplicationID       types.ID                  `db:"application_id"`
		UserID              types.ID                  `db:"user_id,omitempty"`
		Scope               oauth.Scope               `db:"scope,omitempty"`
		Passcode            *string                   `db:"passcode,omitempty"`
		ExpiresAt           oauth.Time                `db:"expires_at"`
		CodeChallenge       oauth.PKCEChallenge       `db:"code_challenge"`
		LoginAttempts       *int                      `db:"login_attempts"`
		CodeChallengeMethod oauth.PKCEChallengeMethod `db:"code_challenge_method"`
		AppURI              oauth.URI                 `db:"app_uri"`
		RedirectURI         *oauth.URI                `db:"redirect_uri"`
		State               *string                   `db:"state,omitempty"`
	}

	accessToken struct {
		ID            types.ID       `db:"id"`
		Issuer        *oauth.URI     `db:"issuer"`
		UserID        *types.ID      `db:"user_id,omitempty"`
		Audience      types.ID       `db:"audience_id"`
		ApplicationID types.ID       `db:"application_id"`
		Use           oauth.TokenUse `db:"token_use"`
		AuthTime      *oauth.Time    `db:"-"`
		Scope         oauth.Scope    `db:"scope"`
		CreatedAt     oauth.Time     `db:"created_at"`
		ExpiresAt     *oauth.Time    `db:"expires_at"`
		Revokable     bool           `db:"-"`
		RevokedAt     *oauth.Time    `db:"revoked_at"`
		Claims        oauth.Claims   `db:"claims"`
		Bearer        *string        `db:"-"`
	}
)

// OAuthController returns an oauth controller from a hiro.Backend
func (b *Backend) OAuthController() oauth.Controller {
	return &oauthController{
		Backend: b,
	}
}

// AudienceGet returns an audience by id
func (o *oauthController) AudienceGet(ctx context.Context, id string) (oauth.Audience, error) {
	var params AudienceGetInput

	if types.ID(id).Valid() {
		params.AudienceID = ptr.ID(id)
	} else {
		params.Name = &id
	}

	aud, err := o.Backend.AudienceGet(ctx, params)
	if err != nil {
		return nil, err
	}

	return &oauthAudience{aud}, nil
}

// ClientGet gets the client from the controller
func (o *oauthController) ClientGet(ctx context.Context, id string, secret ...string) (oauth.Client, error) {
	app, err := o.ApplicationGet(ctx, ApplicationGetInput{
		ApplicationID: ptr.ID(id),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauth.ErrClientNotFound
		}
		return nil, err
	}

	if len(secret) > 0 && secret[0] != "" && app.SecretKey != nil && *app.SecretKey != secret[0] {
		return nil, oauth.ErrAccessDenied
	}

	return &oauthClient{app}, nil
}

// RequestTokenCreate creates a new authentication request
func (o *oauthController) RequestTokenCreate(ctx context.Context, req oauth.RequestToken) (string, error) {
	var out requestToken

	log := o.Log(ctx).WithField("operation", "RequestCreate").WithField("application", req.ClientID)

	if err := o.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new request token")

		audID := types.ID(req.Audience)

		if !audID.Valid() {
			aud, err := o.Backend.AudienceGet(ctx, AudienceGetInput{
				Name: &req.Audience,
			})
			if err != nil {
				return err
			}

			audID = aud.ID
		}

		stmt, args, err := sq.Insert("hiro.request_tokens").
			Columns(
				"type",
				"audience_id",
				"application_id",
				"user_id",
				"scope",
				"passcode",
				"expires_at",
				"code_challenge",
				"code_challenge_method",
				"app_uri",
				"redirect_uri",
				"state").
			Values(
				req.Type,
				audID,
				types.ID(req.ClientID),
				types.ID(req.Subject),
				req.Scope,
				req.Passcode,
				req.ExpiresAt.Time(),
				req.CodeChallenge,
				req.CodeChallengeMethod,
				req.AppURI,
				null.String(req.RedirectURI),
				null.String(req.State),
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(`RETURNING *`).
			ToSql()
		if err != nil {
			log.Error(err.Error())

			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &out, stmt, args...); err != nil {
			log.Error(err.Error())

			return parseSQLError(err)
		}

		return nil
	}); err != nil {
		return "", err
	}

	return out.ID.String(), nil
}

// RequestTokenGet looks up a request by id
func (o *oauthController) RequestTokenGet(ctx context.Context, id string, t ...oauth.RequestTokenType) (oauth.RequestToken, error) {
	var out requestToken

	log := o.Log(ctx).WithField("operation", "RequestGet").
		WithField("id", id)

	if err := o.Transact(ctx, func(ctx context.Context, tx DB) error {
		query := sq.Select("*").
			From("hiro.request_tokens").
			PlaceholderFormat(sq.Dollar).
			Where(sq.Eq{"id": types.ID(id)}).
			Suffix("FOR UPDATE")

		if len(t) > 0 {
			query = query.Where(sq.Eq{"type": t[0]})
		}

		stmt, args, err := query.ToSql()
		if err != nil {
			log.Error(err.Error())

			return parseSQLError(err)
		}

		if err := tx.GetContext(ctx, &out, stmt, args...); err != nil {
			log.Error(err.Error())

			if errors.Is(err, sql.ErrNoRows) {
				return oauth.ErrInvalidToken
			}

			return parseSQLError(err)
		}

		// all tokens except login are one-time-use
		if out.Type != oauth.RequestTokenTypeLogin {
			return o.RequestTokenDelete(ctx, out.ID.String())
		}

		if safe.Int(out.LoginAttempts) > o.passwords.MaxLoginAttempts() {
			err = o.RequestTokenDelete(ctx, out.ID.String())

			return ErrTxCommit(oauth.ErrAccessDenied.
				WithDetail("too many login attempts").
				WithError(err))
		}

		_, err = sq.Update("hiro.request_tokens").
			Set("login_attempts", safe.Int(out.LoginAttempts)+1).
			Where(sq.Eq{"id": types.ID(id)}).
			PlaceholderFormat(sq.Dollar).
			RunWith(tx).
			ExecContext(ctx)

		return nil
	}); err != nil {
		return oauth.RequestToken{}, err
	}

	return oauth.RequestToken{
		ID:                  out.ID,
		Type:                out.Type,
		CreatedAt:           out.CreatedAt,
		Audience:            out.Audience.String(),
		ClientID:            out.ApplicationID.String(),
		Subject:             out.UserID.String(),
		Scope:               out.Scope,
		Passcode:            out.Passcode,
		ExpiresAt:           out.ExpiresAt,
		CodeChallenge:       out.CodeChallenge,
		CodeChallengeMethod: out.CodeChallengeMethod,
		AppURI:              out.AppURI,
		RedirectURI:         out.RedirectURI,
		State:               out.State,
	}, nil
}

// RequestTokenDelete deletes a request token by id
func (o *oauthController) RequestTokenDelete(ctx context.Context, id string) error {

	db := o.DB(ctx)

	_, err := sq.Delete("hiro.request_tokens").
		Where(sq.Eq{"id": types.ID(id)}).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx)

	return err
}

// TokenCreate creates a new token
func (o *oauthController) TokenCreate(ctx context.Context, token oauth.Token) (oauth.Token, error) {
	log := o.Log(ctx).WithField("operation", "TokenCreate").WithField("application", token.ClientID)

	var p AudienceGetInput
	if !types.ID(token.Audience).Valid() {
		p.Name = &token.Audience
	} else {
		p.AudienceID = ptr.ID(token.Audience)
	}

	aud, err := o.Backend.AudienceGet(ctx, p)
	if err != nil {
		return token, err
	}

	token.ID = types.NewID()
	token.Audience = aud.ID.String()
	token.IssuedAt = oauth.Time(time.Now())

	if token.ExpiresAt == nil {
		token.ExpiresAt = oauth.Time(time.Now().Add(aud.TokenSecret.Lifetime)).Ptr()
	}

	if token.Claims == nil {
		token.Claims = make(oauth.Claims)
	}

	if !token.Revokable {
		// ensure revokable tokens have a valid time
		if token.ExpiresAt.Time().IsZero() {
			token.ExpiresAt = oauth.Time(time.Now().Add(aud.TokenSecret.Lifetime)).Ptr()
		}

		log.Debugf("token %s [%s] initialized", token.ID, token.Use)

		return token, nil
	}

	var out accessToken

	if err := o.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new access token")

		stmt, args, err := sq.Insert("hiro.access_tokens").
			Columns(
				"id",
				"issuer",
				"audience_id",
				"application_id",
				"user_id",
				"token_use",
				"scope",
				"claims",
				"expires_at").
			Values(
				token.ID,
				token.Issuer,
				aud.ID,
				types.ID(token.ClientID),
				ptr.ID(token.Subject),
				token.Use,
				token.Scope,
				token.Claims,
				null.Time(token.ExpiresAt),
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(`RETURNING *`).
			ToSql()
		if err != nil {
			log.Error(err.Error())

			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &out, stmt, args...); err != nil {
			log.Error(err.Error())

			return parseSQLError(err)
		}

		return nil
	}); err != nil {
		return oauth.Token{}, err
	}

	log.Debugf("token %s [%s] created", token.ID, token.Use)

	return oauth.Token{
		ID:        out.ID,
		Issuer:    out.Issuer,
		Subject:   ptr.NilString(out.UserID),
		Audience:  out.Audience.String(),
		ClientID:  out.ApplicationID.String(),
		Use:       out.Use,
		Scope:     out.Scope,
		IssuedAt:  out.CreatedAt,
		ExpiresAt: out.ExpiresAt,
		Revokable: true,
		RevokedAt: out.RevokedAt,
		Claims:    out.Claims,
	}, nil
}

// TokenGet gets a token by id
func (o *oauthController) TokenGet(ctx context.Context, id string, use ...oauth.TokenUse) (oauth.Token, error) {
	var out accessToken

	log := o.Log(ctx).WithField("operation", "TokenGet").
		WithField("id", id)

	if err := o.Transact(ctx, func(ctx context.Context, tx DB) error {
		query := sq.Select("*").
			From("hiro.access_tokens").
			PlaceholderFormat(sq.Dollar).
			Where(sq.Eq{"id": types.ID(id)})

		if len(use) > 0 {
			query = query.Where(sq.Eq{"use": use})
		}

		stmt, args, err := query.ToSql()
		if err != nil {
			log.Error(err.Error())

			return parseSQLError(err)
		}

		if err := tx.GetContext(ctx, &out, stmt, args...); err != nil {
			log.Error(err.Error())

			if errors.Is(err, sql.ErrNoRows) {
				return oauth.ErrInvalidToken
			}

			return parseSQLError(err)
		}

		if out.ExpiresAt.Time().Before(time.Now()) {
			return oauth.ErrExpiredToken
		}

		if out.RevokedAt != nil {
			return oauth.ErrRevokedToken
		}

		return nil
	}); err != nil {
		return oauth.Token{}, err
	}

	return oauth.Token{
		ID:        out.ID,
		Issuer:    out.Issuer,
		Subject:   ptr.NilString(out.UserID),
		Audience:  out.Audience.String(),
		ClientID:  out.ApplicationID.String(),
		Use:       out.Use,
		Scope:     out.Scope,
		IssuedAt:  out.CreatedAt,
		ExpiresAt: out.ExpiresAt,
		Revokable: true,
		RevokedAt: out.RevokedAt,
		Claims:    out.Claims,
	}, nil
}

// TokenRevoke revokes a token by id
func (o *oauthController) TokenRevoke(ctx context.Context, id types.ID) error {
	log := o.Log(ctx).
		WithField("operation", "TokenRevoke").
		WithField("token_id", id)

	db := o.DB(ctx)

	if _, err := sq.Update("hiro.access_tokens").
		Where(
			sq.Eq{"id": id},
		).
		Set("revoked_at", time.Now()).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to revoke access token: %s", err)
		return parseSQLError(err)
	}

	log.Debugf("access token revoked")

	return nil
}

// TokenRevokeAll will remove all tokens for a subject
func (o *oauthController) TokenRevokeAll(ctx context.Context, sub string, uses ...oauth.TokenUse) error {
	log := o.Log(ctx).
		WithField("operation", "TokenRevokeAll")

	query := sq.Update("hiro.access_tokens").
		Where(sq.Eq{"user_id": types.ID(sub)})

	if len(uses) > 0 {
		query = query.Where(sq.Eq{"token_use": uses})
	}

	db := o.DB(ctx)

	if _, err := query.
		Set("revoked_at", time.Now()).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to revoke access token: %s", err)
		return parseSQLError(err)
	}

	log.Debugf("access tokens revoked")

	return nil
}

// TokenCleanup should remove any expired or revoked tokens from the store
func (o *oauthController) TokenCleanup(ctx context.Context) error {
	log := o.Log(ctx).WithField("operation", "TokenCleanup")

	log.Debugf("cleaning up request tokens")

	db := o.DB(ctx)

	if _, err := sq.Delete("hiro.request_tokens").
		Where(
			sq.LtOrEq{"expires_at": time.Now()},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to cleanup request tokens %s", err)
		return parseSQLError(err)
	}

	log.Debugf("cleaning up access tokens")

	if _, err := sq.Delete("hiro.access_tokens").
		Where(
			sq.Or{
				sq.Expr("revoked_at IS NOT NULL"),
				sq.LtOrEq{"expires_at": time.Now()},
			},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to cleanup access tokens %s", err)
		return parseSQLError(err)
	}

	return nil
}

// UserGet gets a user by id
func (o *oauthController) UserGet(ctx context.Context, sub string) (oauth.User, error) {
	var in UserGetInput

	if types.ID(sub).Valid() {
		in.UserID = ptr.ID(sub)
	} else {
		in.Login = &sub
	}
	user, err := o.Backend.UserGet(ctx, in)
	if err != nil {
		return nil, err
	}
	return &oauthUser{user}, nil
}

// UserAuthenticate authenticates a user
func (o *oauthController) UserAuthenticate(ctx context.Context, login, password string) (oauth.User, error) {
	user, err := o.Backend.UserGet(ctx, UserGetInput{
		Login: &login,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauth.ErrUserNotFound
		}
		return nil, err
	}

	if user.PasswordHash == nil {
		return nil, oauth.ErrAccessDenied.WithDetail("password not set")
	}

	if !o.passwords.CheckPasswordHash(password, *user.PasswordHash) {
		return nil, oauth.ErrAccessDenied
	}

	return &oauthUser{user}, nil
}

// UserSetPassword sets the users password
func (o *oauthController) UserSetPassword(ctx context.Context, sub, password string) error {
	_, err := o.Backend.UserUpdate(ctx, UserUpdateInput{
		UserID:            types.ID(sub),
		Password:          &password,
		PasswordExpiresAt: ptr.Time(time.Now().Add(o.passwords.PasswordExpiry())),
	})

	return err
}

// UserCreate creates a user
func (o *oauthController) UserCreate(ctx context.Context, login string, password *string, req oauth.RequestToken) (oauth.User, error) {
	var roles []string

	switch req.Type {
	case oauth.RequestTokenTypeLogin:
		roles = []string{"user"}

	case oauth.RequestTokenTypeInvite:
		roles = req.Scope
	}

	user, err := o.Backend.UserCreate(ctx, UserCreateInput{
		Login:             login,
		Password:          password,
		PasswordExpiresAt: ptr.Time(time.Now().Add(o.passwords.PasswordExpiry())),
		Roles:             roles,
	})
	if err != nil {
		return nil, err
	}

	return &oauthUser{user}, nil
}

// UserUpdate updates a user's profile
func (o *oauthController) UserUpdate(ctx context.Context, sub string, profile *openid.Profile) error {
	_, err := o.Backend.UserUpdate(ctx, UserUpdateInput{
		UserID:  types.ID(sub),
		Profile: profile,
	})

	return err
}

// UserVerify should create a email with the verification link for the user
func (o *oauthController) UserNotify(ctx context.Context, note oauth.Notification) error {
	o.Log(ctx).WithField("operation", "UserNotify").
		WithField("type", note.Type()).
		WithField("sub", note.Subject()).
		WithField("channels", note.Channels())

	switch note.Type() {
	case oauth.NotificationTypeVerify:
		log.Debugf("link: %s", note.URI())

	case oauth.NotificationTypePassword:
		log.Debugf("link: %s, code %s", note.URI(), note.(oauth.PasswordNotification).Code())

	case oauth.NotificationTypeInvite:
	}

	return nil
}

func (u oauthUser) Subject() string {
	return u.ID.String()
}

func (u oauthUser) Profile() *openid.Profile {
	return u.User.Profile
}

func (u oauthUser) Permissions(aud oauth.Audience) oauth.Scope {
	return u.User.Permissions.Get(aud.Name())
}

// ClientID returns the client id
func (c oauthClient) ClientID() string {
	return c.ID.String()
}

// ClientType returns the client type
func (c oauthClient) Type() oauth.ClientType {
	return c.Application.Type
}

// Authorize authorizes the client for the specified grants, uris, and scopes
// Used for authorization_code flows
func (c oauthClient) Authorize(ctx context.Context, aud oauth.Audience, grant oauth.GrantType, uris []oauth.URI, scopes ...oauth.Scope) error {
	if grant != oauth.GrantTypeNone {
		if g, ok := c.Grants[aud.Name()]; ok {
			if !g.Contains(grant) {
				return oauth.ErrAccessDenied.WithMessage("grant type % not authorized for audience %s", grant, aud)
			}
		}
	}

	for _, uri := range uris {
		found := false

		u, err := uri.Parse()
		if err != nil {
			return api.ErrBadRequest.WithMessage("%w: uri %s is invalid", err, u.String())
		}

		for _, appURI := range c.URIs {
			uu, _ := appURI.Parse()
			if uu.Scheme == u.Scheme && u.Host == uu.Host {
				if ok, _ := filepath.Match(uu.Path, u.Path); ok {
					found = true
					break
				}
			}
		}

		if !found {
			return oauth.ErrAccessDenied.WithMessage("%s is not an authorized uri", u.String())
		}
	}

	perms, ok := c.Permissions[aud.Name()]
	if !ok {
		return oauth.ErrAccessDenied.WithMessage("client is not authorized for audience %s", aud)
	}

	for _, s := range scopes {
		if !perms.Every(s...) {
			return oauth.ErrAccessDenied.WithMessage("client has insufficient access for request")
		}
	}

	return nil
}

func (a oauthAudience) ID() string {
	return a.Audience.ID.String()
}

func (a oauthAudience) Name() string {
	return a.Audience.Name
}

func (a oauthAudience) Secret() oauth.TokenSecret {
	return *a.TokenSecret
}

func (a oauthAudience) Permissions() oauth.Scope {
	return a.Audience.Permissions
}
