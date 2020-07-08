/*
 * Copyright (C) 2020 Model Rocket
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

// Package postgres is an postgres sql db implementation of the api interface
package postgres

import (
	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/caarlos0/env"
	"github.com/jmoiron/sqlx"
	"github.com/mitchellh/mapstructure"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/sirupsen/logrus"

	// Load the PostgreSQL driver
	_ "github.com/lib/pq"
)

type (
	// backend implements the backend interface with a timescale datastore
	backend struct {
		db     *sqlx.DB
		log    *logrus.Logger
		config config
		ctrl   hiro.BackendController
	}

	// config defines the backend config
	// The config is provided in the main config yaml file, but is opaque to
	// the API service, which provide it as a map[string]interface{}.
	// It is marshaled to a structure by this library.
	//
	//	backend:
	//		db: "postrgres:password@localhost/hiro?ssl_mode=disabled"
	//
	config struct {
		// DBSource is the database source connection string
		DB string `mapstructure:"db" env:"DB_SOURCE"`
	}
)

func init() {
	hiro.RegisterBackend(New)
}

// New returns a new  sql backend instance
func New(params map[string]interface{}, ctrl hiro.BackendController) (hiro.Backend, error) {
	config := config{}

	if err := mapstructure.Decode(params, &config); err != nil {
		return nil, err
	}

	// bring in the env overrides
	if err := env.Parse(&config); err != nil {
		return nil, err
	}

	db, err := sqlx.Connect("postgres", config.DB)
	if err != nil {
		return nil, err
	}

	if _, err := Migrate(db.DB, "postgres", migrate.Up); err != nil {
		return nil, err
	}

	return &backend{
		db:     db,
		log:    ctrl.Log(),
		config: config,
		ctrl:   ctrl,
	}, nil
}
