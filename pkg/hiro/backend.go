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

	"github.com/ModelRocket/hiro/db"
	"github.com/ModelRocket/sparks/pkg/oauth"
	"github.com/ModelRocket/reno/pkg/env"
	"github.com/ModelRocket/reno/pkg/ptr"
	"github.com/ModelRocket/sparks/pkg/api"
	"github.com/apex/log"
	"github.com/jmoiron/sqlx"
	migrate "github.com/rubenv/sql-migrate"
)

type (
	// Backend is the hiro api backend implementation
	Backend struct {
		dbSource      string
		db            *sqlx.DB
		automigrate   bool
		initialize    bool
		audiencces    []AudienceInitializeInput
		timeout       time.Duration
		retryInterval time.Duration
		log           log.Interface
		passwords     PasswordManager
		migrations    []Migration
	}

	// BackendOption defines a backend option
	BackendOption func(b *Backend)

	contextKey string
)

var (
	// Scopes is the spec defined oauth 2.0 scopes for the Hiro API
	Scopes = oauth.Scope{
		"audience:read",
		"audience:write",
		"application:read",
		"application:write",
		"user:read",
		"user:write",
		"token:read",
		"token:write",
		"session:read",
		"session:write",
	}

	// Roles is the list of hiro roles by name
	Roles = oauth.ScopeSet{
		"admin": Scopes,
	}

	contextKeyHiro contextKey = "hiro:context"
)

const (
	// DefaultTokenAlgorithm is the default token algorithm
	DefaultTokenAlgorithm = oauth.TokenAlgorithmRS256

	// DefaultTokenLifetime is the default audience token lifetime
	DefaultTokenLifetime = time.Hour

	// DefaultSessionLifetime is the default audience session lifetime
	DefaultSessionLifetime = time.Hour * 24 * 30
)

// New returns a new hiro backend
func New(opts ...BackendOption) (*Backend, error) {
	const (
		localSource          = "postgres://postgres:password@localhost/hiro?sslmode=disable"
		defaultTimeout       = time.Second * 90
		defaultRetryInterval = time.Second * 3
	)

	var (
		defaultSource = env.Get("DB_SOURCE", localSource)
	)

	b := &Backend{
		dbSource:      defaultSource,
		timeout:       defaultTimeout,
		retryInterval: defaultRetryInterval,
		automigrate:   false,
		initialize:    false,
		log:           log.Log,
		passwords:     DefaultPasswordManager,
		migrations:    make([]Migration, 0),
	}

	for _, opt := range opts {
		opt(b)
	}

	if b.db == nil {
		conn, err := sqlx.Open("postgres", b.dbSource)
		if err != nil {
			return nil, err
		}

		if err := conn.Ping(); err != nil {
			t := time.NewTicker(b.timeout)

		ping:
			for {
				select {
				case <-t.C:
					b.log.Error("database connection timeout")

					return nil, ErrDatabaseTimeout

				case <-time.After(b.retryInterval):
					if err := conn.Ping(); err == nil {
						break ping
					}
					b.log.Warnf("database connection error: %s, retry %s", err, b.retryInterval.String())
				}
			}
		}

		b.db = conn
	}

	if b.automigrate {
		// always migrate hiro first
		if _, err := db.Migrate(b.db.DB, "postgres", "hiro", db.Migrations, migrate.Up); err != nil {
			return nil, err
		}

		// migrate any other sources
		for _, m := range b.migrations {
			if _, err := db.Migrate(b.db.DB, "postgres", m.Schema, m.AssetMigrationSource, migrate.Up); err != nil {
				return nil, err
			}
		}
	}

	if b.initialize {
		if _, err := b.AudienceInitialize(context.Background(), AudienceInitializeInput{
			Name:            "hiro",
			TokenAlgorithm:  DefaultTokenAlgorithm.Ptr(),
			TokenLifetime:   ptr.Duration(DefaultTokenLifetime),
			SessionLifetime: ptr.Duration(DefaultSessionLifetime),
			Permissions:     append(Scopes, oauth.Scopes...),
		}); err != nil {
			return nil, err
		}

		for _, a := range b.audiencces {
			if _, err := b.AudienceInitialize(context.Background(), a); err != nil {
				return nil, err
			}
		}
	}

	return b, nil
}

// Log returns the log from the context or from the server
func (b *Backend) Log(ctx context.Context) log.Interface {
	if api.IsRequest(ctx) {
		return api.Log(ctx)
	}

	return b.log
}

// Context returns the context with hiro
func (b *Backend) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyHiro, b)
}

// PasswordManager returns the current password manager for the instance
func (b *Backend) PasswordManager() PasswordManager {
	return b.passwords
}

// FromContext returns a hiro from the context
func FromContext(ctx context.Context) *Backend {
	h, ok := ctx.Value(contextKeyHiro).(*Backend)
	if ok {
		return h
	}
	return nil
}

// WithLog sets the log for the backend
func WithLog(l log.Interface) BackendOption {
	return func(b *Backend) {
		b.log = l
	}
}

// WithDB sets the database instance
func WithDB(db *sql.DB) BackendOption {
	return func(b *Backend) {
		b.db = sqlx.NewDb(db, "postgres")
	}
}

// WithDBSource sets the database source string
func WithDBSource(source string) BackendOption {
	return func(b *Backend) {
		if source != "" {
			b.dbSource = source
		}
	}
}

// Automigrate will perform the database initialization, creating tables and indexes.
func Automigrate(m ...Migration) BackendOption {
	return func(b *Backend) {
		b.automigrate = true
		b.migrations = append(b.migrations, m...)
	}
}

// Initialize will create the default hiro audience and application to use for management
func Initialize(a ...AudienceInitializeInput) BackendOption {
	return func(b *Backend) {
		b.initialize = true
		b.audiencces = a
	}
}
