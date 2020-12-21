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

	"github.com/ModelRocket/hiro/db"
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/env"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/safe"
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
		timeout       time.Duration
		retryInterval time.Duration
		log           log.Interface
		passwords     PasswordManager
	}

	// BackendOption defines a backend option
	BackendOption func(b *Backend)

	contextKey string
)

var (
	// Roles is the list of hiro roles by name
	Roles = []string{"admin", "user"}

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

	contextKeyHiro contextKey = "hiro:context"
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
		if _, err := db.Migrate(b.db.DB, "postgres", migrate.Up); err != nil {
			return nil, err
		}
	}

	if b.initialize {
		aud, err := b.AudienceCreate(context.Background(), AudienceCreateInput{
			Name:            "hiro",
			TokenAlgorithm:  oauth.TokenAlgorithmRS256,
			TokenLifetime:   time.Hour,
			SessionLifetime: time.Hour * 24 * 30,
			Permissions:     append(Scopes, oauth.Scopes...),
		})
		if err != nil && !errors.Is(err, ErrDuplicateObject) {
			return nil, err
		}

		b.log.Infof("audience hiro [%s] initialized", aud.ID)

		if len(aud.TokenSecrets) == 0 {
			if _, err := b.SecretCreate(context.Background(), SecretCreateInput{
				AudienceID: aud.ID,
				Type:       SecretTypeToken,
				Algorithm:  oauth.TokenAlgorithmRS256.Ptr(),
			}); err != nil {
				return nil, fmt.Errorf("%w: failed to create audience secret", err)
			}
		}

		if len(aud.SessionKeys) == 0 {
			if _, err := b.SecretCreate(context.Background(), SecretCreateInput{
				AudienceID: aud.ID,
				Type:       SecretTypeSession,
			}); err != nil {
				return nil, fmt.Errorf("%w: failed to create audience secret", err)
			}
		}

		app, err := b.ApplicationCreate(context.Background(), ApplicationCreateInput{
			Name: "hiro:app",
			Permissions: oauth.ScopeSet{
				"hiro": append(Scopes, oauth.Scopes...),
			},
			Grants: oauth.Grants{
				"hiro": {oauth.GrantTypeClientCredentials, oauth.GrantTypeAuthCode, oauth.GrantTypeRefreshToken},
			},
		})
		if err != nil && !errors.Is(err, ErrDuplicateObject) {
			return nil, err
		}

		b.log.Infof("application hiro:app initialized, client_id = %q, client_secret=%q", app.ID, safe.String(app.SecretKey))
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
func Automigrate() BackendOption {
	return func(b *Backend) {
		b.automigrate = true
	}
}

// Initialize will create the default hiro audience and application to use for management
func Initialize() BackendOption {
	return func(b *Backend) {
		b.initialize = true
	}
}
