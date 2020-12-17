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
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/api/session"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/types"
	"github.com/gorilla/sessions"
)

type (
	sessionController struct {
		*Backend
	}

	dbSession struct {
		ID        types.ID   `db:"id"`
		Audience  types.ID   `db:"audience_id"`
		Subject   types.ID   `db:"user_id"`
		Data      string     `db:"data"`
		CreatedAt time.Time  `db:"created_at"`
		ExpiresAt time.Time  `db:"expires_at"`
		RevokedAt *time.Time `db:"revoked_at,omitempty"`
	}
)

// SessionController returns an oauth controller from a hiro.Backend
func (b *Backend) SessionController() session.Controller {
	return &sessionController{
		Backend: b,
	}
}

// SessionCreate creates a session
func (s *sessionController) SessionCreate(ctx context.Context, sess *session.Session) error {
	var out dbSession

	log := api.Log(ctx).WithField("operation", "SessionCreate").WithField("user_id", sess.Subject)

	var p AudienceGetInput
	if !sess.Audience.Valid() {
		p.Name = ptr.String(sess.Audience)
	} else {
		p.AudienceID = &sess.Audience
	}

	aud, err := s.Backend.AudienceGet(ctx, p)
	if err != nil {
		return err
	}

	if err := s.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new session")

		stmt, args, err := sq.Insert("hiro.sessions").
			Columns(
				"audience_id",
				"user_id",
				"data",
				"expires_at").
			Values(
				aud.ID,
				sess.Subject,
				sess.Data,
				time.Now().Add(aud.SessionLifetime),
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
		return err
	}

	*sess = session.Session(out)

	return nil
}

// SessionUpdate saves a session
func (s *sessionController) SessionUpdate(ctx context.Context, sess *session.Session) error {
	var out dbSession

	log := api.Log(ctx).WithField("operation", "SessionUpdate").
		WithField("session_id", sess.ID).
		WithField("user_id", sess.Subject)

	if err := s.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating session")

		stmt, args, err := sq.Update("hiro.sessions").
			Set("data", sess.Data).
			Set("expires_at", sess.ExpiresAt).
			Where(sq.Eq{"id": sess.ID}).
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
		return err
	}

	*sess = session.Session(out)

	return nil
}

// SessionLoad gets a session by id
func (s *sessionController) SessionLoad(ctx context.Context, id types.ID) (session.Session, error) {
	var out dbSession

	log := api.Log(ctx).WithField("operation", "SessionLoad").
		WithField("id", id)

	if err := s.Transact(ctx, func(ctx context.Context, tx DB) error {

		stmt, args, err := sq.Select("*").
			From("hiro.sessions").
			PlaceholderFormat(sq.Dollar).
			Where(sq.Eq{"id": id}).
			ToSql()
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

		// delete expired sessions as we come accross them
		if out.ExpiresAt.Before(time.Now()) {
			_, err = sq.Delete("hiro.sessions").
				Where(sq.Eq{"id": id}).
				PlaceholderFormat(sq.Dollar).
				RunWith(tx).
				ExecContext(ctx)
		}

		return err
	}); err != nil {
		return session.Session{}, err
	}

	return session.Session(out), nil
}

func (s *sessionController) SessionDestroy(ctx context.Context, id types.ID) error {
	db := s.Backend.DB(ctx)

	if _, err := sq.Delete("hiro.sessions").
		Where(sq.Eq{"id": id}).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		return err
	}

	return nil
}

func (s *sessionController) SessionOptions(ctx context.Context, id types.ID) (session.Options, error) {
	var p AudienceGetInput
	if !id.Valid() {
		p.Name = ptr.String(id)
	} else {
		p.AudienceID = &id
	}

	aud, err := s.Backend.AudienceGet(ctx, p)
	if err != nil {
		return session.Options{}, err
	}

	opts := session.Options{
		Options: sessions.Options{
			MaxAge: int(aud.SessionLifetime.Seconds()),
		},
	}
	copy(opts.Hash[:], ([]byte(aud.ID))[0:32])
	copy(opts.Block[:], aud.TokenSecret.Bytes()[0:32])

	return opts, nil
}
