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
	"encoding/json"

	"github.com/Teralytic/teralytic/pkg/teralytic"
	"github.com/jmoiron/sqlx/types"
)

// OptionCreate stores a named option in the backend data store
func (b *backend) OptionCreate(name string, value interface{}) error {
	v, err := json.Marshal(value)
	if err != nil {
		return err
	}

	if _, err := b.db.Exec(
		`INSERT INTO options (name, value) VALUES($1, $2) ON CONFLICT (name) DO NOTHING`,
		name,
		types.JSONText(v)); err != nil {
		return err
	}

	return nil
}

// OptionUpdate stores a named option in the backend data store
func (b *backend) OptionUpdate(name string, value interface{}) error {
	v, err := json.Marshal(value)
	if err != nil {
		return err
	}

	if _, err := b.db.Exec(
		`INSERT INTO options (name, value) VALUES($1, $2) ON CONFLICT (name) DO UPDATE SET value=$3`,
		name,
		types.JSONText(v),
		types.JSONText(v)); err != nil {
		return err
	}

	return nil
}

// OptionGet returns a named option from the backend
func (b *backend) OptionGet(name string, out interface{}) error {
	data := make([]byte, 0)

	query := b.db.QueryRow(`SELECT value FROM options WHERE name=$1`, name)

	if err := query.Scan(&data); err != nil {
		if err == sql.ErrNoRows {
			return teralytic.ErrOptionNotFound
		}
		return err
	}

	return json.Unmarshal(data, out)
}

// OptionRemove removes the named option from the backend
func (b *backend) OptionRemove(name string) error {
	_, err := b.db.Exec(`DELETE FROM options WHERE name=$1`, name)

	return err
}
