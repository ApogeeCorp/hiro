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

	// RequestToken is the backend representation of an oauth.RequestToken
	RequestToken struct {
		ID                  ID                        `json:"id" db:"id"`
		Type                oauth.RequestTokenType    `json:"type" db:"type"`
		CreatedAt           oauth.Time                `json:"created_at" db:"created_at"`
		Audience            ID                        `json:"audience_id" db:"audience_id"`
		ApplicationID       ID                        `json:"application_id" db:"application_id"`
		UserID              ID                        `json:"user_id,omitempty" db:"user_id"`
		Scope               oauth.Scope               `json:"scope,omitempty" db:"scope"`
		Passcode            *string                   `json:"passcode,omitempty" db:"passcode"`
		ExpiresAt           oauth.Time                `json:"expires_at" db:"expires_at"`
		CodeChallenge       oauth.PKCEChallenge       `json:"code_challenge,omitempty" db:"code_challenge"`
		CodeChallengeMethod oauth.PKCEChallengeMethod `json:"code_challenge_method,omitempty" db:"code_challenge_method"`
		LoginAttempts       *int                      `json:"login_attempts,omitempty" db:"login_attempts"`
		AppURI              *oauth.URI                `json:"app_uri,omitempty" db:"app_uri"`
		RedirectURI         *oauth.URI                `json:"redirect_uri,omitempty" db:"redirect_uri"`
		State               *string                   `json:"state,omitempty" db:"state"`
	}

	// AccessToken is the backend representation of an oauth.Token (type=TokenTypeAccess)
	AccessToken struct {
		ID            ID             `json:"id" db:"id"`
		Issuer        *oauth.URI     `json:"issuer,omitempty" db:"issuer"`
		Audience      ID             `json:"audience_id" db:"audience_id"`
		ApplicationID ID             `json:"application_id" db:"application_id"`
		UserID        ID             `json:"user_id,omitempty" db:"user_id,omitempty"`
		Use           oauth.TokenUse `json:"token_use" db:"token_use"`
		AuthTime      *oauth.Time    `db:"-"`
		Scope         oauth.Scope    `json:"scope,omitempty" db:"scope"`
		CreatedAt     oauth.Time     `json:"created_at" db:"created_at"`
		ExpiresAt     *oauth.Time    `json:"expires_at,omitempty" db:"expires_at"`
		Revokable     bool           `db:"-"`
		RevokedAt     *oauth.Time    `json:"revoked_at,omitempty" db:"revoked_at"`
		Claims        oauth.Claims   `json:"claims,omitempty" db:"claims"`
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

	if ID(id).Valid() {
		params.AudienceID = ID(id)
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
		ApplicationID: ID(id),
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
	var out RequestToken

	log := o.Log(ctx).WithField("operation", "RequestCreate").WithField("application", req.ClientID)

	if err := o.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new request token")

		audID := ID(req.Audience)

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
				ID(req.ClientID),
				NullID(req.Subject),
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

			return ParseSQLError(err)
		}

		return nil
	}); err != nil {
		return "", err
	}

	return out.ID.String(), nil
}

// RequestTokenGet looks up a request by id
func (o *oauthController) RequestTokenGet(ctx context.Context, id string, t ...oauth.RequestTokenType) (oauth.RequestToken, error) {
	var out RequestToken

	log := o.Log(ctx).WithField("operation", "RequestGet").
		WithField("id", id)

	if err := o.Transact(ctx, func(ctx context.Context, tx DB) error {
		query := sq.Select("*").
			From("hiro.request_tokens").
			PlaceholderFormat(sq.Dollar).
			Where(sq.Eq{"id": ID(id)}).
			Suffix("FOR UPDATE")

		if len(t) > 0 {
			query = query.Where(sq.Eq{"type": t[0]})
		}

		stmt, args, err := query.ToSql()
		if err != nil {
			log.Error(err.Error())

			return ParseSQLError(err)
		}

		if err := tx.GetContext(ctx, &out, stmt, args...); err != nil {
			log.Error(err.Error())

			if errors.Is(err, sql.ErrNoRows) {
				return oauth.ErrInvalidToken
			}

			return ParseSQLError(err)
		}

		// all tokens except login are one-time-use
		if out.Type != oauth.RequestTokenTypeLogin {
			return o.RequestTokenDelete(ctx, out.ID.String())
		}

		if safe.Int(out.LoginAttempts) >= o.passwords.MaxLoginAttempts() {
			err = o.RequestTokenDelete(ctx, out.ID.String())

			return ErrTxCommit(
				oauth.NewErrTooManyLoginAttempts(*out.LoginAttempts).WithError(err))
		}

		_, err = sq.Update("hiro.request_tokens").
			Set("login_attempts", safe.Int(out.LoginAttempts)+1).
			Where(sq.Eq{"id": ID(id)}).
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
		Subject:             ptr.String(out.UserID),
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
		Where(sq.Eq{"id": ID(id)}).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx)

	return err
}

// TokenCreate creates a new token
func (o *oauthController) TokenCreate(ctx context.Context, token oauth.Token) (oauth.Token, error) {
	log := o.Log(ctx).WithField("operation", "TokenCreate").WithField("application", token.ClientID)

	var p AudienceGetInput
	if !ID(token.Audience).Valid() {
		p.Name = &token.Audience
	} else {
		p.AudienceID = NullID(token.Audience)
	}

	aud, err := o.Backend.AudienceGet(ctx, p)
	if err != nil {
		return token, err
	}

	tokenID := NullID()
	token.ID = tokenID.String()
	token.Audience = aud.ID.String()
	token.IssuedAt = oauth.Time(time.Now())

	if token.ExpiresAt == nil {
		token.ExpiresAt = oauth.Time(time.Now().Add(aud.TokenLifetime)).Ptr()
	}

	if token.Claims == nil {
		token.Claims = make(oauth.Claims)
	}

	if !token.Revokable {
		// ensure revokable tokens have a valid time
		if token.ExpiresAt.Time().IsZero() {
			token.ExpiresAt = oauth.Time(time.Now().Add(aud.TokenLifetime)).Ptr()
		}

		log.Debugf("token %s [%s] initialized", token.ID, token.Use)

		return token, nil
	}

	var out AccessToken

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
				tokenID,
				token.Issuer,
				aud.ID,
				ID(token.ClientID),
				NullID(token.Subject),
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

			return ParseSQLError(err)
		}

		return nil
	}); err != nil {
		return oauth.Token{}, err
	}

	log.Debugf("token %s [%s] created", token.ID, token.Use)

	return oauth.Token{
		ID:        out.ID.String(),
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
	var out AccessToken

	log := o.Log(ctx).WithField("operation", "TokenGet").
		WithField("id", id)

	if err := o.Transact(ctx, func(ctx context.Context, tx DB) error {
		query := sq.Select("*").
			From("hiro.access_tokens").
			PlaceholderFormat(sq.Dollar).
			Where(sq.Eq{"id": ID(id)})

		if len(use) > 0 {
			query = query.Where(sq.Eq{"use": use})
		}

		stmt, args, err := query.ToSql()
		if err != nil {
			log.Error(err.Error())

			return ParseSQLError(err)
		}

		if err := tx.GetContext(ctx, &out, stmt, args...); err != nil {
			log.Error(err.Error())

			if errors.Is(err, sql.ErrNoRows) {
				return oauth.ErrInvalidToken
			}

			return ParseSQLError(err)
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
		ID:        out.ID.String(),
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
func (o *oauthController) TokenRevoke(ctx context.Context, id string) error {
	log := o.Log(ctx).
		WithField("operation", "TokenRevoke").
		WithField("token_id", id)

	db := o.DB(ctx)

	if _, err := sq.Update("hiro.access_tokens").
		Where(
			sq.Eq{"id": ID(id)},
		).
		Set("revoked_at", time.Now()).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to revoke access token: %s", err)
		return ParseSQLError(err)
	}

	log.Debugf("access token revoked")

	return nil
}

// TokenRevokeAll will remove all tokens for a subject
func (o *oauthController) TokenRevokeAll(ctx context.Context, sub string, uses ...oauth.TokenUse) error {
	log := o.Log(ctx).
		WithField("operation", "TokenRevokeAll")

	query := sq.Update("hiro.access_tokens").
		Where(sq.Eq{"user_id": ID(sub)})

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
		return ParseSQLError(err)
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
		return ParseSQLError(err)
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
		return ParseSQLError(err)
	}

	return nil
}

// UserGet gets a user by id
func (o *oauthController) UserGet(ctx context.Context, sub string) (oauth.User, error) {
	var in UserGetInput

	if ID(sub).Valid() {
		in.UserID = ID(sub)
	} else {
		in.Login = &sub
	}

	user, err := o.Backend.UserGet(ctx, in)
	if err != nil {
		return nil, err
	}

	if user.LockedUntil != nil {
		if user.LockedUntil.After(time.Now()) {
			return nil, oauth.ErrAccessDenied.
				WithDetail("user account locked").
				WithDetail(user.LockedUntil.String())
		}

		p := UserUpdateInput{
			LockedUntil: ptr.Time(time.Unix(0, 0)),
		}

		if ID(sub).Valid() {
			p.UserID = ID(sub)
		} else {
			p.Login = &sub
		}

		o.Backend.UserUpdate(ctx, p)
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

	if user.LockedUntil != nil {
		if user.LockedUntil.After(time.Now()) {
			return nil, oauth.ErrAccessDenied.
				WithDetail("user account locked").
				WithDetail(user.LockedUntil.String())
		}

		o.Backend.UserUpdate(ctx, UserUpdateInput{
			Login:       &login,
			LockedUntil: ptr.Time(time.Unix(0, 0)),
		})
	}

	if !o.passwords.CheckPasswordHash(password, *user.PasswordHash) {
		return nil, oauth.ErrAccessDenied
	}

	return &oauthUser{user}, nil
}

// UserLockout should lock a user for the specified time or default
func (o *oauthController) UserLockout(ctx context.Context, sub string, until ...time.Time) (time.Time, error) {
	u := time.Now().Add(o.passwords.AccountLockoutPeriod())

	if len(until) > 0 {
		u = until[0]
	}

	p := UserUpdateInput{
		LockedUntil: &u,
	}

	if ID(sub).Valid() {
		p.UserID = ID(sub)
	} else {
		p.Login = &sub
	}

	_, err := o.Backend.UserUpdate(ctx, p)

	return u, err
}

// UserSetPassword sets the users password
func (o *oauthController) UserSetPassword(ctx context.Context, sub, password string) error {
	p := UserUpdateInput{
		Password:          &password,
		PasswordExpiresAt: ptr.Time(time.Now().Add(o.passwords.PasswordExpiry())),
	}

	if ID(sub).Valid() {
		p.UserID = ID(sub)
	} else {
		p.Login = &sub
	}

	_, err := o.Backend.UserUpdate(ctx, p)

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
	p := UserUpdateInput{
		Profile: profile,
	}

	if ID(sub).Valid() {
		p.UserID = ID(sub)
	} else {
		p.Login = &sub
	}

	_, err := o.Backend.UserUpdate(ctx, p)

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
		return oauth.ErrAccessDenied.WithMessage("client is not authorized for audience %s", aud.Name())
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

func (a oauthAudience) Secrets() []oauth.TokenSecret {
	rval := make([]oauth.TokenSecret, 0)
	for _, s := range a.TokenSecrets {
		if s.Algorithm() == oauth.TokenAlgorithmRS256 {
			rval = append(rval, s)
		}
	}

	return rval
}

func (a oauthAudience) Permissions() oauth.Scope {
	return a.Audience.Permissions
}

func (a oauthAudience) RefreshTokenLifetime() time.Duration {
	return a.SessionLifetime
}
