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
	"encoding/json"

	"github.com/ModelRocket/hiro/pkg/hiro"
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
			return hiro.ErrOptionNotFound
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
