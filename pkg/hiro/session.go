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
	"github.com/ModelRocket/hiro/pkg/api/session"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/gorilla/sessions"
)

type (
	sessionController struct {
		Controller
	}

	// Session is the backend store representation of session.Session
	Session struct {
		ID         ID         `json:"id" db:"id"`
		InstanceID ID         `json:"instance_id" db:"instance_id"`
		UserID     ID         `json:"user_id" db:"user_id"`
		Data       string     `json:"data" db:"data"`
		CreatedAt  time.Time  `json:"created_at" db:"created_at"`
		ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
		RevokedAt  *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	}

	// SessionKey is a wrapper around a token secret
	SessionKey Secret
)

// SessionCreate creates a session
func (h *Hiro) SessionCreate(ctx context.Context, sess *session.Session) error {
	var out Session

	log := Log(ctx).WithField("operation", "SessionCreate").WithField("user_id", sess.Subject)

	inst, err := h.InstanceGet(ctx, InstanceGetInput{
		Audience: &sess.Audience,
	})
	if err != nil {
		return err
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new session")

		stmt, args, err := sq.Insert("hiro.sessions").
			Columns(
				"instance_id",
				"user_id",
				"data",
				"expires_at").
			Values(
				inst.ID,
				ID(sess.Subject),
				sess.Data,
				time.Now().Add(inst.SessionLifetime),
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
		return err
	}

	*sess = session.Session{
		ID:        out.ID.String(),
		Audience:  out.InstanceID.String(),
		Subject:   out.UserID.String(),
		Data:      out.Data,
		CreatedAt: out.CreatedAt,
		ExpiresAt: out.ExpiresAt,
		RevokedAt: out.RevokedAt,
	}

	return nil
}

// SessionUpdate saves a session
func (h *Hiro) SessionUpdate(ctx context.Context, sess *session.Session) error {
	var out Session

	log := Log(ctx).WithField("operation", "SessionUpdate").
		WithField("session_id", sess.ID).
		WithField("user_id", sess.Subject)

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating session")

		stmt, args, err := sq.Update("hiro.sessions").
			Set("data", sess.Data).
			Set("expires_at", sess.ExpiresAt).
			Where(sq.Eq{"id": ID(sess.ID)}).
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
		return err
	}

	*sess = session.Session{
		ID:        out.ID.String(),
		Audience:  out.InstanceID.String(),
		Subject:   out.UserID.String(),
		Data:      out.Data,
		CreatedAt: out.CreatedAt,
		ExpiresAt: out.ExpiresAt,
		RevokedAt: out.RevokedAt,
	}

	return nil
}

// SessionLoad gets a session by id
func (h *Hiro) SessionLoad(ctx context.Context, id string) (session.Session, error) {
	var out Session

	log := Log(ctx).WithField("operation", "SessionLoad").
		WithField("id", id)

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {

		stmt, args, err := sq.Select("*").
			From("hiro.sessions").
			PlaceholderFormat(sq.Dollar).
			Where(sq.Eq{"id": ID(id)}).
			ToSql()
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

		// delete expired sessions as we come accross them
		if out.ExpiresAt.Before(time.Now()) {
			if _, err := sq.Delete("hiro.sessions").
				Where(sq.Eq{"id": ID(id)}).
				PlaceholderFormat(sq.Dollar).
				RunWith(tx).
				ExecContext(ctx); err != nil {
				return err
			}

			return session.ErrSessionExpired
		}

		return err
	}); err != nil {
		return session.Session{}, err
	}

	return session.Session{
		ID:        out.ID.String(),
		Audience:  out.InstanceID.String(),
		Subject:   out.UserID.String(),
		Data:      out.Data,
		CreatedAt: out.CreatedAt,
		ExpiresAt: out.ExpiresAt,
		RevokedAt: out.RevokedAt,
	}, nil
}

func (h *Hiro) SessionDestroy(ctx context.Context, id string) error {
	db := h.DB(ctx)

	if _, err := sq.Delete("hiro.sessions").
		Where(sq.Eq{"id": ID(id)}).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		return err
	}

	return nil
}

func (h *Hiro) SessionOptions(ctx context.Context, id string) (session.Options, error) {
	inst, err := h.InstanceGet(ctx, InstanceGetInput{
		InstanceID: (*ID)(&id),
	})
	if err != nil {
		return session.Options{}, err
	}

	opts := session.Options{
		Options: sessions.Options{
			MaxAge:   int(inst.SessionLifetime.Seconds()),
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
		},
		KeyPairs: make([][]byte, 0),
	}

	for _, k := range inst.SessionKeys {

		opts.KeyPairs = append(opts.KeyPairs, k.Hash(), k.Block())
	}

	return opts, nil
}

// SessionCleanup removes expired sessions
func (h *Hiro) SessionCleanup(ctx context.Context) error {
	log := Log(ctx).WithField("operation", "SessionCleanup")

	log.Debug("cleaning up sessions")

	db := h.DB(ctx)

	if _, err := sq.Delete("hiro.sessions").
		Where(
			sq.LtOrEq{"expires_at": time.Now()},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to cleanup request tokens %s", err)
		return ParseSQLError(err)
	}

	return nil
}

// Hash returns the session key hash
func (s SessionKey) Hash() []byte {
	v := []byte(s.RawKey)

	return v[0:32]
}

// Block returns the session key block
func (s SessionKey) Block() []byte {
	v := []byte(s.RawKey)

	return v[32:64]
}
