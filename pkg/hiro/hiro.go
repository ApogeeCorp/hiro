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

// Package hiro is a foundational component for Model Rocket platform API services
package hiro

import (
	"context"
	"database/sql"
	"time"

	"github.com/ModelRocket/hiro/db"
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/env"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/apex/log"
	"github.com/jmoiron/sqlx"
	migrate "github.com/rubenv/sql-migrate"
)

type (
	// Hiro is the hiro api backend implementation
	Hiro struct {
		dbSource      string
		db            *sqlx.DB
		assetVolume   string
		automigrate   bool
		initialize    bool
		timeout       time.Duration
		retryInterval time.Duration
		passwords     PasswordManager
		migrations    []SchemaMigration
	}

	// HiroOption defines a backend option
	HiroOption func(b *Hiro)

	contextKey string
)

var (
	// Scopes is the spec defined oauth 2.0 scopes for the Hiro API
	Scopes = append(oauth.Scopes,
		ScopeInstanceRead,
		ScopeInstanceWrite,
		ScopeApplicationRead,
		ScopeApplicationWrite,
		ScopeUserRead,
		ScopeUserWrite,
		ScopeTokenRead,
		ScopeTokenCreate,
		ScopeTokenRevoke,
		ScopeSessionRead,
		ScopeSessionRevoke,
		ScopeRoleRead,
		ScopeRoleWrite,
		ScopeAssetRead,
		ScopeAssetWrite,
	)

	ScopesReadOnly = append(oauth.Scopes,
		ScopeInstanceRead,
		ScopeApplicationRead,
		ScopeUserRead,
		ScopeTokenRead,
		ScopeTokenCreate,
		ScopeTokenRevoke,
		ScopeSessionRead,
		ScopeSessionRevoke,
		ScopeRoleRead,
		ScopeAssetRead,
	)

	// Roles is the list of hiro roles by name
	Roles = map[string]oauth.Scope{
		RoleAdmin: Scopes,
		RoleUser:  append(ScopesReadOnly, ScopeUserWrite),
	}

	contextKeyHiro   contextKey = "hiro:context"
	contextKeyLogger contextKey = "hiro:logger"
)

const (
	// DefaultTokenAlgorithm is the default token algorithm
	DefaultTokenAlgorithm = oauth.TokenAlgorithmRS256

	// DefaultTokenLifetime is the default instance token lifetime
	DefaultTokenLifetime = time.Hour

	// DefaultSessionLifetime is the default instance session lifetime
	DefaultSessionLifetime = time.Hour * 24

	// DefaultRefreshTokenLifetime is the default refresh token lifetime
	DefaultRefreshTokenLifetime = time.Hour * 24 * 7

	// DefaultLoginTokenLifetime is the default login token lifetime used for magic links, etc
	DefaultLoginTokenLifetime = time.Minute * 15

	// DefaultInviteTokenLifetime is  the token lifetime for invitation links
	DefaultInviteTokenLifetime = time.Hour * 24 * 7

	// DefaultVerifyTokenLifetime is the default two-factor verification code lifetime
	DefaultVerifyTokenLifetime = time.Hour * 24

	// DefaultAuthCodeLifetime is the default lifetime for oauth auth codes
	DefaultAuthCodeLifetime = time.Minute * 10

	// RoleSuperAdmin is the superadmin scope
	RoleSuperAdmin = "superadmin"

	// RoleAdmin is the default admin role name
	RoleAdmin = "admin"

	// RoleUser is the default user role
	RoleUser = "user"
)

// New returns a new hiro backend
func New(opts ...HiroOption) (*Hiro, error) {
	const (
		localSource          = "postgres://postgres:password@localhost/hiro?sslmode=disable"
		defaultTimeout       = time.Second * 90
		defaultRetryInterval = time.Second * 3
	)

	var (
		defaultSource      = env.Get("DB_SOURCE", localSource)
		defaultAssetVolume = env.Get("HIRO_ASSET_VOLUME")
	)

	b := &Hiro{
		dbSource:      defaultSource,
		timeout:       defaultTimeout,
		retryInterval: defaultRetryInterval,
		automigrate:   false,
		initialize:    false,
		passwords:     DefaultPasswordManager,
		migrations:    make([]SchemaMigration, 0),
		assetVolume:   defaultAssetVolume,
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
					log.Error("database connection timeout")

					return nil, ErrDatabaseTimeout

				case <-time.After(b.retryInterval):
					if err := conn.Ping(); err == nil {
						break ping
					}
					log.Warnf("database connection error: %s, retry %s", err, b.retryInterval.String())
				}
			}
		}

		b.db = conn
	}

	if b.automigrate {
		// always migrate hiro first
		if _, err := db.Migrate(b.db.DB, "postgres", "hiro", db.Hiro, migrate.Up); err != nil {
			return nil, err
		}

		// migrate any other sources
		for _, m := range b.migrations {
			if _, err := db.Migrate(b.db.DB, "postgres", m.Schema, m, migrate.Up); err != nil {
				return nil, err
			}
		}
	}

	return b, nil
}

// Context returns the context with hiro
func (h *Hiro) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyHiro, h)
}

// PasswordManager returns the current password manager for the instance
func (h *Hiro) PasswordManager() PasswordManager {
	return h.passwords
}

// FromContext returns a hiro from the context
func FromContext(ctx context.Context) *Hiro {
	h, ok := ctx.Value(contextKeyHiro).(*Hiro)
	if ok {
		return h
	}
	return nil
}

// WithDB sets the database instance
func WithDB(db *sql.DB) HiroOption {
	return func(h *Hiro) {
		h.db = sqlx.NewDb(db, "postgres")
	}
}

// WithDBSource sets the database source string
func WithDBSource(source string) HiroOption {
	return func(h *Hiro) {
		if source != "" {
			h.dbSource = source
		}
	}
}

// WithAssetVolume sets the asset volume for the instance
func WithAssetVolume(v string) HiroOption {
	return func(h *Hiro) {
		h.assetVolume = v
	}
}

// Automigrate will perform the database initialization, creating tables and indexes.
func Automigrate(m ...SchemaMigration) HiroOption {
	return func(h *Hiro) {
		h.automigrate = true
		h.migrations = append(h.migrations, m...)
	}
}

// WithLogger sets a context logger for requests
func WithLogger(ctx context.Context, log log.Interface) context.Context {
	return context.WithValue(ctx, contextKeyLogger, log)
}

// Log returns the log from the context or from the server
func Log(ctx context.Context) log.Interface {
	if api.IsRequest(ctx) {
		return api.Log(ctx)
	}

	if l, ok := ctx.Value(contextKeyLogger).(log.Interface); ok {
		return l
	}

	return log.Log
}
