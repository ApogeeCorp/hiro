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
	"time"

	sq "github.com/Masterminds/squirrel"

	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/apex/log"
)

type (
	oauthController struct {
		*Hiro
	}

	// RequestToken is the backend representation of an oauth.RequestToken
	RequestToken struct {
		ID                  ID                        `json:"id" db:"id"`
		Type                oauth.RequestTokenType    `json:"type" db:"type"`
		CreatedAt           time.Time                 `json:"created_at" db:"created_at"`
		InstanceID          ID                        `json:"instance_id" db:"instance_id"`
		Audience            string                    `json:"audience" db:"audience"`
		ApplicationID       ID                        `json:"application_id" db:"application_id"`
		ClientID            string                    `json:"client_id" db:"client_id"`
		UserID              ID                        `json:"user_id,omitempty" db:"user_id"`
		Scope               oauth.Scope               `json:"scope,omitempty" db:"scope"`
		Passcode            *string                   `json:"passcode,omitempty" db:"passcode"`
		ExpiresAt           *time.Time                `json:"expires_at" db:"expires_at"`
		CodeChallenge       oauth.PKCEChallenge       `json:"code_challenge,omitempty" db:"code_challenge"`
		CodeChallengeMethod oauth.PKCEChallengeMethod `json:"code_challenge_method,omitempty" db:"code_challenge_method"`
		LoginAttempts       *int                      `json:"login_attempts,omitempty" db:"login_attempts"`
		AppURI              *string                   `json:"app_uri,omitempty" db:"app_uri"`
		RedirectURI         *string                   `json:"redirect_uri,omitempty" db:"redirect_uri"`
		State               *string                   `json:"state,omitempty" db:"state"`
	}

	// AccessToken is the backend representation of an oauth.Token (type=TokenTypeAccess)
	AccessToken struct {
		ID            ID             `json:"id" db:"id"`
		Issuer        *string        `json:"issuer,omitempty" db:"issuer"`
		InstanceID    ID             `json:"instance_id" db:"instance_id"`
		Audience      string         `json:"audience" db:"audience"`
		ApplicationID ID             `json:"application_id" db:"application_id"`
		ClientID      string         `json:"client_id" db:"client_id"`
		UserID        ID             `json:"user_id,omitempty" db:"user_id,omitempty"`
		Use           oauth.TokenUse `json:"token_use" db:"token_use"`
		AuthTime      *time.Time     `db:"-"`
		Scope         oauth.Scope    `json:"scope,omitempty" db:"scope"`
		CreatedAt     time.Time      `json:"created_at" db:"created_at"`
		ExpiresAt     *time.Time     `json:"expires_at,omitempty" db:"expires_at"`
		Revokable     bool           `db:"-"`
		RevokedAt     *time.Time     `json:"revoked_at,omitempty" db:"revoked_at"`
		Claims        oauth.Claims   `json:"claims,omitempty" db:"claims"`
		Bearer        *string        `db:"-"`
	}
)

func (h *Hiro) OAuthController() oauth.Controller {
	return &oauthController{Hiro: h}
}

// AudienceGet returns an instance by id
func (c *oauthController) AudienceGet(ctx context.Context, params oauth.AudienceGetInput) (oauth.Audience, error) {
	inst, err := c.InstanceGet(ctx, InstanceGetInput{
		Audience: &params.Audience,
	})
	if err != nil {
		return nil, oauth.ErrAudienceNotFound.WithError(err)
	}

	return &oauthAudience{inst}, nil
}

// ClientGet gets the client from the controller
func (c *oauthController) ClientGet(ctx context.Context, params oauth.ClientGetInput) (oauth.Client, error) {
	inst, err := c.InstanceGet(ctx, InstanceGetInput{
		Audience: &params.Audience,
	})
	if err != nil {
		return nil, oauth.ErrAudienceNotFound.WithError(err)
	}

	app, err := c.ApplicationGet(ctx, ApplicationGetInput{
		InstanceID: inst.ID,
		ClientID:   &params.ClientID,
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, oauth.ErrClientNotFound.WithError(err)
		}
		return nil, err
	}

	if params.ClientSecret != nil && app.ClientSecret != nil && *app.ClientSecret != *params.ClientSecret {
		return nil, oauth.ErrUnauthorized
	}

	return &oauthClient{Application: app, inst: inst}, nil
}

// RequestTokenCreate creates a new authentication request
func (c *oauthController) RequestTokenCreate(ctx context.Context, req oauth.RequestToken) (string, error) {
	var out RequestToken

	log := Log(ctx).WithField("operation", "oauth.RequestTokenCreate").WithField("application", req.ClientID)

	inst, err := c.InstanceGet(ctx, InstanceGetInput{
		Audience: &req.Audience,
	})
	if err != nil {
		return "", oauth.ErrAudienceNotFound.WithError(err)
	}

	app, err := c.ApplicationGet(ctx, ApplicationGetInput{
		InstanceID: inst.ID,
		ClientID:   &req.ClientID,
	})
	if err != nil {
		return "", oauth.ErrClientNotFound.WithError(err)
	}

	switch req.Type {
	case oauth.RequestTokenTypeAuthCode:
		req.ExpiresAt = time.Now().Add(inst.AuthCodeLifetime * time.Second).Unix()

	case oauth.RequestTokenTypeLogin:
		req.ExpiresAt = time.Now().Add(inst.LoginTokenLifetime * time.Second).Unix()

	case oauth.RequestTokenTypeSession:
		req.ExpiresAt = time.Now().Add(inst.SessionLifetime * time.Second).Unix()

	case oauth.RequestTokenTypeInvite:
		req.ExpiresAt = time.Now().Add(inst.InviteTokenLifetime * time.Second).Unix()

	case oauth.RequestTokenTypeVerify:
		req.ExpiresAt = time.Now().Add(inst.VerifyTokenLifetime * time.Second).Unix()

	case oauth.RequestTokenTypeRefreshToken:
		req.ExpiresAt = time.Now().Add(inst.RefreshTokenLifetime * time.Second).Unix()
	}

	if err := c.Transact(ctx, func(ctx context.Context, tx DB) error {
		stmt, args, err := sq.Insert("hiro.request_tokens").
			Columns(
				"type",
				"instance_id",
				"audience",
				"application_id",
				"client_id",
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
				inst.ID,
				inst.Audience,
				app.ID,
				app.ClientID,
				NewID(req.Subject),
				req.Scope,
				req.Passcode,
				time.Unix(req.ExpiresAt, 0),
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
func (c *oauthController) RequestTokenGet(ctx context.Context, params oauth.RequestTokenGetInput) (oauth.RequestToken, error) {
	var out RequestToken

	log := Log(ctx).WithField("operation", "RequestTokenGet").WithField("id", params.TokenID)

	if err := c.Transact(ctx, func(ctx context.Context, tx DB) error {
		query := sq.Select("*").
			From("hiro.request_tokens").
			PlaceholderFormat(sq.Dollar).
			Where(sq.Eq{"id": ID(params.TokenID)}).
			Suffix("FOR UPDATE")

		if params.TokenType != nil {
			query = query.Where(sq.Eq{"type": *params.TokenType})
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
			return c.RequestTokenDelete(ctx, oauth.RequestTokenDeleteInput{TokenID: out.ID.String()})
		}

		if safe.Int(out.LoginAttempts) >= c.passwords.MaxLoginAttempts() {
			err = c.RequestTokenDelete(ctx, oauth.RequestTokenDeleteInput{TokenID: out.ID.String()})

			return ErrTxCommit(
				oauth.NewErrTooManyLoginAttempts(*out.LoginAttempts).WithError(err))
		}

		_, err = sq.Update("hiro.request_tokens").
			Set("login_attempts", safe.Int(out.LoginAttempts)+1).
			Where(sq.Eq{"id": ID(params.TokenID)}).
			PlaceholderFormat(sq.Dollar).
			RunWith(tx).
			ExecContext(ctx)

		return err
	}); err != nil {
		return oauth.RequestToken{}, err
	}

	return oauth.RequestToken{
		ID:                  out.ID,
		Type:                out.Type,
		CreatedAt:           out.CreatedAt.Unix(),
		Audience:            out.Audience,
		ClientID:            out.ClientID,
		Subject:             ptr.String(out.UserID),
		Scope:               out.Scope,
		Passcode:            out.Passcode,
		ExpiresAt:           out.ExpiresAt.Unix(),
		CodeChallenge:       out.CodeChallenge,
		CodeChallengeMethod: out.CodeChallengeMethod,
		AppURI:              out.AppURI,
		RedirectURI:         out.RedirectURI,
		State:               out.State,
	}, nil
}

// RequestTokenDelete deletes a request token by id
func (c *oauthController) RequestTokenDelete(ctx context.Context, params oauth.RequestTokenDeleteInput) error {

	db := c.DB(ctx)

	_, err := sq.Delete("hiro.request_tokens").
		Where(sq.Eq{"id": ID(params.TokenID)}).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx)

	return err
}

// TokenCreate creates a new token
func (c *oauthController) TokenCreate(ctx context.Context, token oauth.Token) (oauth.Token, error) {
	log := Log(ctx).WithField("operation", "TokenCreate").WithField("application", token.ClientID)

	inst, err := c.InstanceGet(ctx, InstanceGetInput{
		Audience: &token.Audience,
	})
	if err != nil {
		return token, oauth.ErrAudienceNotFound.WithError(err)
	}

	app, err := c.ApplicationGet(ctx, ApplicationGetInput{
		InstanceID: inst.ID,
		ClientID:   &token.ClientID,
	})
	if err != nil {
		return token, oauth.ErrClientNotFound.WithError(err)
	}

	tokenID := NewID()
	token.ID = tokenID.String()
	token.Audience = inst.Audience
	token.IssuedAt = time.Now().Unix()

	if token.Claims == nil {
		token.Claims = make(oauth.Claims)
	}

	if !token.Revokable {
		token.ExpiresAt = ptr.Int64(time.Now().Add(inst.TokenLifetime))

		log.Debugf("token %s [%s] initialized", token.ID, token.Use)

		return token, nil
	}

	if !token.Persistent {
		token.ExpiresAt = ptr.Int64(time.Now().Add(inst.TokenLifetime))
	}

	var out AccessToken

	if err := c.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new access token")

		stmt, args, err := sq.Insert("hiro.access_tokens").
			Columns(
				"id",
				"issuer",
				"instance_id",
				"audience",
				"application_id",
				"client_id",
				"user_id",
				"token_use",
				"scope",
				"claims",
				"expires_at").
			Values(
				tokenID,
				token.Issuer,
				inst.ID,
				inst.Audience,
				app.ID,
				app.ClientID,
				NewID(token.Subject),
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

	rval := oauth.Token{
		ID:        out.ID.String(),
		Issuer:    out.Issuer,
		Subject:   ptr.NilString(out.UserID),
		Audience:  out.Audience,
		ClientID:  out.ClientID,
		Use:       out.Use,
		Scope:     out.Scope,
		IssuedAt:  out.CreatedAt.Unix(),
		Revokable: true,
		Claims:    out.Claims,
	}

	if out.ExpiresAt != nil {
		rval.ExpiresAt = ptr.Int64(out.ExpiresAt.Unix())
	} else {
		rval.Persistent = true
	}

	return rval, nil
}

// TokenGet gets a token by id
func (c *oauthController) TokenGet(ctx context.Context, params oauth.TokenGetInput) (oauth.Token, error) {
	var out AccessToken

	log := Log(ctx).WithField("operation", "TokenGet").
		WithField("id", params.TokenID)

	if err := c.Transact(ctx, func(ctx context.Context, tx DB) error {
		query := sq.Select("*").
			From("hiro.access_tokens").
			PlaceholderFormat(sq.Dollar).
			Where(sq.Eq{"id": ID(params.TokenID)})

		if params.TokenUse != nil {
			query = query.Where(sq.Eq{"use": *params.TokenUse})
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

		return nil
	}); err != nil {
		return oauth.Token{}, err
	}

	rval := oauth.Token{
		ID:        out.ID.String(),
		Issuer:    out.Issuer,
		Subject:   ptr.NilString(out.UserID),
		Audience:  out.Audience,
		ClientID:  out.ApplicationID.String(),
		Use:       out.Use,
		Scope:     out.Scope,
		IssuedAt:  out.CreatedAt.Unix(),
		Revokable: true,
		Claims:    out.Claims,
	}

	if out.ExpiresAt != nil {
		rval.ExpiresAt = ptr.Int64(out.ExpiresAt.Unix())
	}

	if out.RevokedAt != nil {
		rval.RevokedAt = ptr.Int64(out.RevokedAt.Unix())
	}

	return rval, nil
}

// TokenRevoke revokes a token by id
func (c *oauthController) TokenRevoke(ctx context.Context, params oauth.TokenRevokeInput) error {
	log := Log(ctx).
		WithField("operation", "TokenRevoke").
		WithField("token_id", params.TokenID)

	db := c.DB(ctx)

	where := make(sq.Eq)

	if params.TokenID != nil {
		where["id"] = *params.TokenID
	} else if params.Subject != nil {
		where["user_id"] = ID(*params.Subject)
	} else {
		return oauth.ErrInvalidRequest.WithMessage("token id or subject required")
	}

	if _, err := sq.Update("hiro.access_tokens").
		Where(where).
		Set("revoked_at", time.Now()).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to revoke access token: %s", err)
		return ParseSQLError(err)
	}

	log.Debugf("access token(s) revoked")

	return nil
}

// TokenCleanup should remove any expired or revoked tokens from the store
func (c *oauthController) TokenCleanup(ctx context.Context) error {
	log := Log(ctx).WithField("operation", "TokenCleanup")

	log.Debugf("cleaning up request tokens")

	db := c.DB(ctx)

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
func (c *oauthController) UserGet(ctx context.Context, params oauth.UserGetInput) (oauth.User, error) {
	var in UserGetInput

	inst, err := c.InstanceGet(ctx, InstanceGetInput{
		Audience: &params.Audience,
	})
	if err != nil {
		return nil, oauth.ErrAudienceNotFound.WithError(err)
	}

	if params.Login != nil {
		in.Login = params.Login
	} else if params.Subject != nil {
		in.UserID = ID(*params.Subject)
	} else {
		return nil, oauth.ErrInvalidRequest
	}

	user, err := c.Hiro.UserGet(ctx, in)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, oauth.ErrUserNotFound
		}
		return nil, err
	}

	if user.LockedUntil != nil {
		if user.LockedUntil.After(time.Now()) {
			return nil, oauth.ErrUnauthorized.
				WithCode("user_account_locked").
				WithDetail(user.LockedUntil.String())
		}

		c.Hiro.UserUpdate(ctx, UserUpdateInput{
			LockedUntil: &time.Time{},
		})
	}

	if params.Password != nil {
		if user.PasswordHash == nil {
			return nil, oauth.ErrUnauthorized.WithDetail("password not set")
		}

		if !c.passwords.CheckPasswordHash(*params.Password, *user.PasswordHash) {
			return nil, oauth.ErrUnauthorized
		}
	}

	return &oauthUser{User: user, inst: inst}, nil
}

func (c *oauthController) UserUpdate(ctx context.Context, params oauth.UserUpdateInput) (oauth.User, error) {
	var in UserGetInput

	inst, err := c.InstanceGet(ctx, InstanceGetInput{
		Audience: &params.Audience,
	})
	if err != nil {
		return nil, oauth.ErrAudienceNotFound.WithError(err)
	}

	if params.Login != nil {
		in.Login = params.Login
	} else if params.Subject != nil {
		in.UserID = ID(*params.Subject)
	} else {
		return nil, oauth.ErrInvalidRequest
	}

	user, err := c.Hiro.UserGet(ctx, in)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, oauth.ErrUserNotFound
		}
		return nil, err
	}

	user, err = c.Hiro.UserUpdate(ctx, UserUpdateInput{
		UserID:      user.ID,
		Password:    params.Password,
		Profile:     params.Profile,
		LockedUntil: params.LockUntil,
	})
	if err != nil {
		return nil, err
	}

	return &oauthUser{User: user, inst: inst}, nil
}

// UserCreate creates a user
func (c *oauthController) UserCreate(ctx context.Context, params oauth.UserCreateInput) (oauth.User, error) {
	inst, err := c.InstanceGet(ctx, InstanceGetInput{
		Params: Params{
			Expand: ExpandAll,
		},
		Audience: &params.Audience,
	})
	if err != nil {
		return nil, oauth.ErrAudienceNotFound.WithError(err)
	}

	roles := make([]UserRole, 0)

	for _, r := range inst.Roles {
		if r.Default {
			roles = append(roles, UserRole{
				InstanceID: inst.ID,
				RoleID:     &r.ID,
			})
		}
	}

	user, err := c.Hiro.UserCreate(ctx, UserCreateInput{
		Login:             params.Login,
		Password:          params.Password,
		PasswordExpiresAt: ptr.Time(time.Now().Add(c.PasswordManager().PasswordExpiry())),
		Profile:           params.Profile,
		Roles:             roles,
	})
	if err != nil {
		return nil, err
	}

	return &oauthUser{User: user, inst: inst}, nil
}

// UserVerify should create a email with the verification link for the user
func (h *oauthController) UserNotify(ctx context.Context, note oauth.Notification) error {
	Log(ctx).WithField("operation", "UserNotify").
		WithField("type", note.Type()).
		WithField("sub", note.Subject()).
		WithField("channels", note.Channels())

	switch note.Type() {
	case oauth.NotificationTypeVerify:
		log.Debugf("link: %s", note.Context()["link"])

	case oauth.NotificationTypePassword:
		log.Debugf("link: %s, code %s", note.Context()["link"], note.(oauth.PasswordNotification).Code())

	case oauth.NotificationTypeInvite:
	}

	return nil
}
