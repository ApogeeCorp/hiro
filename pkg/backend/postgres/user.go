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
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/ModelRocket/hiro/api/types"
	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/a8m/rql"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/lib/pq"
)

type (
	// Profile provides sql support for the user profile
	Profile struct {
		*types.Profile
	}

	// Metadata provides sql support for the user metadata
	Metadata map[string]interface{}

	// User is the backend representation of a user
	User struct {
		Login string `db:"login" rql:"filter"`

		PasswordHash string `db:"password_hash" rql:"filter"`

		Permissions pq.StringArray `db:"permissions"`

		Profile Profile `db:"profile,omitempty"`

		CreatedAt strfmt.DateTime `db:"created_at,omitempty"`

		ID string `db:"id,omitempty" rql:"filter"`

		Metadata Metadata `db:"metadata,omitempty"`

		UpdatedAt strfmt.DateTime `db:"updated_at,omitempty"`
	}
)

// UserCreate creates a new user
func (b *backend) UserCreate(user *types.User, password string) error {
	out := &User{}

	row := b.db.QueryRowx(
		`INSERT INTO users 
		(login, password_hash, profile, metadata, permissions)
		VALUES($1, crypt($2, gen_salt('bf', 8)), $3, $4, $5) 
		ON CONFLICT(login) DO NOTHING RETURNING *`,
		user.Login,
		password,
		Profile{user.Profile},
		Metadata(user.Metadata),
		pq.StringArray(user.Permissions),
	)
	if err := row.StructScan(out); err != nil {
		if err == sql.ErrNoRows {
			return hiro.ErrObjectExists
		}
		return err
	}

	*user = out.User()

	return nil
}

// UserAuthenticate populates a user object of one is found with the login and password
func (b *backend) UserAuthenticate(login, password string, user *types.User) error {
	out := &User{}

	row := b.db.QueryRowx(
		`SELECT * FROM users WHERE login=$1 AND password_hash=crypt($2,password_hash)`,
		login,
		password,
	)
	if err := row.StructScan(out); err != nil {
		return err
	}

	*user = out.User()

	return nil
}

// UserGet gets a user
func (b *backend) UserGet(query *rql.Query, user *types.User) error {
	out := &User{}

	parser := rql.MustNewParser(rql.Config{
		Model:            User{},
		ColumnFn:         swag.ToFileName,
		ParamSymbol:      "$",
		PositionalParams: true,
	})

	params, err := parser.ParseQuery(query)
	if err != nil {
		return err
	}

	row := b.db.QueryRowx(
		`SELECT * FROM users WHERE `+params.FilterExp,
		params.FilterArgs...)
	if err := row.StructScan(out); err != nil {
		return err
	}

	*user = out.User()

	return nil
}

// UserUpdate updates a user, this implementation is limited to a users profile, metadata, and permissions
func (b *backend) UserUpdate(query *rql.Query, user *types.User) error {
	out := &User{}

	parser := rql.MustNewParser(rql.Config{
		Model:            User{},
		ColumnFn:         swag.ToFileName,
		ParamSymbol:      "$",
		PositionalParams: true,
		ParamOffset:      4,
	})

	params, err := parser.ParseQuery(query)
	if err != nil {
		return err
	}

	args := []interface{}{
		Profile{user.Profile},
		Metadata(user.Metadata),
		pq.StringArray(user.Permissions),
	}
	args = append(args, params.FilterArgs...)

	row := b.db.QueryRowx(
		`UPDATE users SET
		profile=$1, metadata=$2, permissions=$3
		WHERE `+params.FilterExp+
			` RETURNING *`,
		args...)
	if err := row.StructScan(out); err != nil {
		if err == sql.ErrNoRows {
			return hiro.ErrObjectExists
		}
		return err
	}

	*user = out.User()

	return nil
}

// User converts the backend user to the api user
func (u *User) User() types.User {
	rval := types.User{
		ID: u.ID,

		Login: u.Login,

		Profile: u.Profile.Profile,

		Permissions: u.Permissions,

		Metadata: u.Metadata,

		CreatedAt: u.CreatedAt,

		UpdatedAt: u.UpdatedAt,
	}

	if rval.Profile == nil {
		rval.Profile = &types.Profile{}
	}

	rval.Profile.Sub = rval.ID
	rval.Profile.UpdatedAt = time.Time(rval.UpdatedAt).Unix()

	return rval
}

// Value returns p as a value
func (p Profile) Value() (driver.Value, error) {
	return json.Marshal(p.Profile)
}

// Scan store value in p.Profile
func (p *Profile) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(b, &p.Profile)
}

// Value returns p as a value
func (m Metadata) Value() (driver.Value, error) {
	return json.Marshal(map[string]interface{}(m))
}

// Scan store value in Metadata
func (m *Metadata) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(b, &m)
}
