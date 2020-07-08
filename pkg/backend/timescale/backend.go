//
//  TERALYTIC CONFIDENTIAL
//  _________________
//   2020 TERALYTIC
//   All Rights Reserved.
//
//   NOTICE:  All information contained herein is, and remains
//   the property of TERALYTIC and its suppliers,
//   if any.  The intellectual and technical concepts contained
//   herein are proprietary to TERALYTIC
//   and its suppliers and may be covered by U.S. and Foreign Patents,
//   patents in process, and are protected by trade secret or copyright law.
//   Dissemination of this information or reproduction of this material
//   is strictly forbidden unless prior written permission is obtained
//   from TERALYTIC.
//

// Package timescale is an timescale sql db implementation of the teralytic interface
package timescale

import (
	"github.com/Teralytic/teralytic/pkg/teralytic"
	"github.com/caarlos0/env"
	"github.com/jmoiron/sqlx"
	"github.com/mitchellh/mapstructure"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/sirupsen/logrus"

	// Load the PostgreSQL driver
	_ "github.com/lib/pq"
)

type (
	// backend implements the Teralytic interface with a timescale datastore
	backend struct {
		db     *sqlx.DB
		log    *logrus.Logger
		config config
		ctrl   teralytic.BackendController
	}

	// config defines the teralytic backend config
	// The config is provided in the main config yaml file, but is opaque to
	// the Teralytic service, which provide it as a map[string]interface{}.
	// It is marshaled to a structure by this library.
	//
	//	backend:
	//		db: "postrgres:password@localhost/teralytic?ssl_mode=disabled"
	//
	config struct {
		// DBSource is the database source connection string
		DB string `mapstructure:"db" env:"DB_SOURCE"`
	}
)

func init() {
	teralytic.RegisterBackend(New)
}

// New returns a new teralytic sql backend instance
func New(params map[string]interface{}, ctrl teralytic.BackendController) (teralytic.Backend, error) {
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
