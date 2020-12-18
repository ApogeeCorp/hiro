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
	"github.com/ModelRocket/hiro/pkg/types"
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
		ClientID            types.ID                  `db:"application_id"`
		Subject             types.ID                  `db:"user_id,omitempty"`
		Scope               oauth.Scope               `db:"scope,omitempty"`
		ExpiresAt           oauth.Time                `db:"expires_at"`
		CodeChallenge       oauth.PKCEChallenge       `db:"code_challenge"`
		CodeChallengeMethod oauth.PKCEChallengeMethod `db:"code_challenge_method"`
		AppURI              oauth.URI                 `db:"app_uri"`
		RedirectURI         *oauth.URI                `db:"redirect_uri"`
		State               *string                   `db:"state,omitempty"`
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
func (o *oauthController) ClientGet(ctx context.Context, id types.ID, secret ...string) (oauth.Client, error) {
	app, err := o.ApplicationGet(ctx, ApplicationGetInput{
		ApplicationID: &id,
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

		if !req.Audience.Valid() {
			aud, err := o.Backend.AudienceGet(ctx, AudienceGetInput{
				Name: ptr.String(req.Audience),
			})
			if err != nil {
				return err
			}

			req.Audience = aud.ID
		}
		stmt, args, err := sq.Insert("hiro.request_tokens").
			Columns(
				"type",
				"audience_id",
				"application_id",
				"user_id",
				"scope",
				"expires_at",
				"code_challenge",
				"code_challenge_method",
				"app_uri",
				"redirect_uri",
				"state").
			Values(
				req.Type,
				req.Audience,
				req.ClientID,
				req.Subject,
				req.Scope,
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
func (o *oauthController) RequestTokenGet(ctx context.Context, id types.ID, t ...oauth.RequestTokenType) (oauth.RequestToken, error) {
	var req requestToken

	log := o.Log(ctx).WithField("operation", "RequestGet").
		WithField("id", id)

	if err := o.Transact(ctx, func(ctx context.Context, tx DB) error {
		query := sq.Select("*").
			From("hiro.request_tokens").
			PlaceholderFormat(sq.Dollar).
			Where(sq.Eq{"id": id}).
			Suffix("FOR UPDATE")

		if len(t) > 0 {
			query = query.Where(sq.Eq{"type": t[0]})
		}

		stmt, args, err := query.ToSql()
		if err != nil {
			log.Error(err.Error())

			return parseSQLError(err)
		}

		if err := tx.GetContext(ctx, &req, stmt, args...); err != nil {
			log.Error(err.Error())

			if errors.Is(err, sql.ErrNoRows) {
				return oauth.ErrInvalidToken
			}

			return parseSQLError(err)
		}

		_, err = sq.Delete("hiro.request_tokens").
			Where(sq.Eq{"id": types.ID(id)}).
			PlaceholderFormat(sq.Dollar).
			RunWith(tx).
			ExecContext(ctx)

		return err
	}); err != nil {
		return oauth.RequestToken{}, err
	}

	return oauth.RequestToken(req), nil
}

// TokenCreate creates a new token
func (o *oauthController) TokenCreate(ctx context.Context, token oauth.Token) (oauth.Token, error) {
	log := o.Log(ctx).WithField("operation", "TokenCreate").WithField("application", token.ClientID)

	var p AudienceGetInput
	if !token.Audience.Valid() {
		p.Name = ptr.String(token.Audience)
	} else {
		p.AudienceID = &token.Audience
	}

	aud, err := o.Backend.AudienceGet(ctx, p)
	if err != nil {
		return token, err
	}

	token.ID = ptr.ID(types.NewID())
	token.Audience = aud.ID
	token.IssuedAt = oauth.Time(time.Now())
	token.ExpiresAt = oauth.Time(time.Now().Add(aud.TokenSecret.Lifetime)).Ptr()

	if token.Claims == nil {
		token.Claims = make(oauth.Claims)
	}

	log.Debugf("token %s [%s] initialized", token.ID, token.Use)

	return token, nil
}

// UserGet gets a user by id
func (o *oauthController) UserGet(ctx context.Context, id types.ID) (oauth.User, error) {
	user, err := o.Backend.UserGet(ctx, UserGetInput{
		UserID: &id,
	})
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

// UserCreate creates a user
func (o *oauthController) UserCreate(ctx context.Context, login, password string, req oauth.RequestToken) (oauth.User, error) {
	var roles []string

	switch req.Type {
	case oauth.RequestTokenTypeLogin:
		roles = []string{"user"}

	case oauth.RequestTokenTypeInvite:
		roles = req.Scope
	}

	user, err := o.Backend.UserCreate(ctx, UserCreateInput{
		Login:             login,
		Password:          &password,
		PasswordExpiresAt: ptr.Time(time.Now().Add(o.passwords.PasswordExpiry())),
		Roles:             roles,
	})
	if err != nil {
		return nil, err
	}

	return &oauthUser{user}, nil
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

	return nil
}

func (u oauthUser) SubjectID() types.ID {
	return u.ID
}

func (u oauthUser) Profile() *openid.Profile {
	return u.User.Profile
}

func (u oauthUser) Permissions(aud oauth.Audience) oauth.Scope {
	return u.User.Permissions.Get(aud.Name())
}

// ClientID returns the client id
func (c oauthClient) ClientID() types.ID {
	return c.ID
}

// ClientType returns the client type
func (c oauthClient) Type() oauth.ClientType {
	return c.Application.Type
}

// Authorize authorizes the client for the specified grants, uris, and scopes
// Used for authorization_code flows
func (c oauthClient) Authorize(ctx context.Context, aud oauth.Audience, grant oauth.GrantType, uris []oauth.URI, scopes ...oauth.Scope) error {
	if g, ok := c.Grants[aud.Name()]; ok {
		if !g.Contains(grant) {
			return oauth.ErrAccessDenied.WithMessage("grant type % not authorized for audience %s", grant, aud)
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

func (a oauthAudience) ID() types.ID {
	return a.Audience.ID
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
