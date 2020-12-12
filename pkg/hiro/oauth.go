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
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/types"
)

// ClientGet gets the client from the controller
func (b *Backend) ClientGet(ctx context.Context, id string) (oauth.Client, error) {
	return b.ApplicationGet(ctx, ApplicationGetInput{
		ApplicationID: ptr.ID(id),
	})
}

// RequestCreate creates a new authentication request
func (b *Backend) RequestCreate(ctx context.Context, req oauth.Request) (string, error) {
	log := api.Log(ctx).WithField("operation", "RequestCreate").WithField("application", req.ApplicationID)

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new request token")

		if !req.AudienceID.Valid() {
			aud, err := b.AudienceGet(ctx, AudienceGetInput{
				Name: ptr.String(req.AudienceID),
			})
			if err != nil {
				return err
			}

			req.AudienceID = aud.ID
		}
		stmt, args, err := sq.Insert("hiro.request_tokens").
			Columns(
				"audience_id",
				"application_id",
				"scope",
				"expires_at",
				"code_challenge",
				"code_challenge_method",
				"app_uri",
				"redirect_uri",
				"state").
			Values(
				req.AudienceID,
				req.ApplicationID,
				req.Scope,
				req.ExpiresAt,
				req.CodeChallenge,
				req.CodeChallengeMethod,
				req.AppURI,
				req.RedirectURI,
				null.String(req.State),
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(`RETURNING *`).
			ToSql()
		if err != nil {
			log.Error(err.Error())

			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &req, stmt, args...); err != nil {
			log.Error(err.Error())

			return parseSQLError(err)
		}

		return nil
	}); err != nil {
		return "", err
	}

	return req.ID.String(), nil
}

// RequestGet looks up a request by id
func (b *Backend) RequestGet(ctx context.Context, id string) (*oauth.Request, error) {
	log := api.Log(ctx).WithField("operation", "RequestGet").
		WithField("id", id)

	db := b.DB(ctx)

	query := sq.Select("*").
		From("hiro.request_tokens").
		PlaceholderFormat(sq.Dollar).
		Where(sq.Eq{"id": types.ID(id)})

	stmt, args, err := query.
		ToSql()
	if err != nil {
		log.Error(err.Error())

		return nil, parseSQLError(err)
	}

	var req oauth.Request

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(&req); err != nil {
		log.Error(err.Error())

		return nil, parseSQLError(err)
	}

	return &req, nil
}

// TokenCreate creates a new token
func (b *Backend) TokenCreate(ctx context.Context, token *oauth.AccessToken) error {
	return nil
}

// TokenFinalize finalizes the token and returns the signed and encoded token
func (b *Backend) TokenFinalize(ctx context.Context, token *oauth.AccessToken) (string, error) {
	return "", nil
}
