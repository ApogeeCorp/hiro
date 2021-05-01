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
	"embed"
	"io/fs"
	"net/http"

	migrate "github.com/rubenv/sql-migrate"
)

var (
	//go:embed sql/*.sql
	migrationFS embed.FS

	// Hiro is the migrations for Hiro
	Hiro migrate.MigrationSource
)

func init() {
	rel, err := fs.Sub(migrationFS, "sql")
	if err != nil {
		panic(err)
	}

	Hiro = &migrate.HttpFileSystemMigrationSource{
		FileSystem: http.FS(rel),
	}
}

// Migrate processes the database migrations
func Migrate(db *sql.DB, dialect string, schema string, source migrate.MigrationSource, dir migrate.MigrationDirection) (int, error) {
	migrate.SetTable("db_migrations")
	migrate.SetSchema(schema)
	return migrate.Exec(db, dialect, source, dir)
}
