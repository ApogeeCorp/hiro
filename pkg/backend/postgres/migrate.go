/*
 * Copyright (C) 2020 Model Rocket
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package postgres

import (
	"database/sql"

	migrate "github.com/rubenv/sql-migrate"
)

//go:generate go-bindata -pkg=postgres ./sql/
var (
	migrations = &migrate.AssetMigrationSource{
		Asset:    Asset,
		AssetDir: AssetDir,
		Dir:      "sql",
	}
)

// Migrate processes the database migrations
func Migrate(db *sql.DB, dialect string, dir migrate.MigrationDirection) (int, error) {
	migrate.SetTable("db_migrations")
	return migrate.Exec(db, dialect, migrations, dir)
}
