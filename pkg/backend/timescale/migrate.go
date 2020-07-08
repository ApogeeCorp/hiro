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

package timescale

import (
	"database/sql"

	migrate "github.com/rubenv/sql-migrate"
)

//go:generate go-bindata -pkg=timescale ./sql/
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
