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
	"time"

	"github.com/ModelRocket/hiro/api/spec"
	"github.com/ModelRocket/hiro/db"
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/apex/log"
	"github.com/jmoiron/sqlx"
	migrate "github.com/rubenv/sql-migrate"
)

type (
	// Hiro is the hiro api backend implementation
	Hiro struct {
		dbSource      string
		db            *sqlx.DB
		automigrate   bool
		initialize    bool
		timeout       time.Duration
		retryInterval time.Duration
		log           log.Interface
	}

	// Option defines a backend option
	Option func(b *Hiro)

	contextKey string
)

var (
	// Roles is the list of atomic roles by name
	Roles = []string{"admin", "user"}

	// Scopes is the spec defined oauth 2.0 scopes for the Hiro API
	Scopes = make([]string, 0)

	passwordValidationEnabled = true

	contextKeyHiro contextKey = "hiro:context"
)

func init() {
	for key, def := range spec.SpecDoc.Spec().SecurityDefinitions {
		if def.Type != "oauth2" || key != "Hiro" {
			continue
		}

		for scope := range def.Scopes {
			Scopes = append(Scopes, scope)
		}
	}
}

// New returns a new hiro backend
func New(opts ...Option) (*Hiro, error) {
	const (
		defaultSource        = "postgres://postgres:password@db/hiro?sslmode=disable"
		defaultTimeout       = time.Second * 90
		defaultRetryInterval = time.Second * 3
	)

	h := &Hiro{
		dbSource:      defaultSource,
		timeout:       defaultTimeout,
		retryInterval: defaultRetryInterval,
		automigrate:   false,
		initialize:    false,
		log:           log.Log,
	}

	for _, opt := range opts {
		opt(h)
	}

	if h.db == nil {
		conn, err := sqlx.Open("postgres", h.dbSource)
		if err != nil {
			return nil, err
		}

		if err := conn.Ping(); err != nil {
			t := time.NewTicker(h.timeout)

		ping:
			for {
				select {
				case <-t.C:
					h.log.Error("database connection timeout")

					return nil, ErrDatabaseTimeout

				case <-time.After(h.retryInterval):
					if err := conn.Ping(); err == nil {
						break ping
					}
					h.log.Warnf("database connection error: %s, retry %s", err, h.retryInterval.String())
				}
			}
		}

		h.db = conn
	}

	if h.automigrate {
		if _, err := db.Migrate(h.db.DB, "postgres", migrate.Up); err != nil {
			return nil, err
		}
	}

	return h, nil
}

// Log returns the log from the context or from the server
func (h *Hiro) Log(ctx context.Context) log.Interface {
	if api.IsRequest(ctx) {
		return api.Log(ctx)
	}

	return h.log
}

// Context returns the context with hiro
func (h *Hiro) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyHiro, h)
}

// FromContext returns a hiro from the context
func FromContext(ctx context.Context) *Hiro {
	h, ok := ctx.Value(contextKeyHiro).(*Hiro)
	if ok {
		return h
	}
	return nil
}

// WithLog sets the log for the backend
func WithLog(l log.Interface) Option {
	return func(h *Hiro) {
		h.log = l
	}
}

// WithDB sets the database instance
func WithDB(db *sql.DB) Option {
	return func(h *Hiro) {
		h.db = sqlx.NewDb(db, "postgres")
	}
}

// WithDBSource sets the database source string
func WithDBSource(source string) Option {
	return func(h *Hiro) {
		if source != "" {
			h.dbSource = source
		}
	}
}

// Automigrate will perform the database initialization, creating tables and indexes.
func Automigrate() Option {
	return func(h *Hiro) {
		h.automigrate = true
	}
}
