/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://github.com/ModelRocket/hiro
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

package db

import (
	"database/sql"

	migrate "github.com/rubenv/sql-migrate"
)

//go:generate go-bindata -pkg=db ./sql/
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
	migrate.SetSchema("hiro")
	return migrate.Exec(db, dialect, migrations, dir)
}
