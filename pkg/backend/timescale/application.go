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

	"github.com/Teralytic/teralytic/api/types"
	"github.com/Teralytic/teralytic/pkg/teralytic"
	"github.com/a8m/rql"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/mr-tron/base58"
	"github.com/thoas/go-funk"
)

type (
	// Application is the postgres representation of the types.Application
	Application struct {
		AllowedGrants pq.StringArray `db:"allowed_grants"`

		ClientID string `db:"client_id,omitempty" rql:"filter"`

		ClientSecret string `db:"client_secret,omitempty" rql:"filter"`

		Description string `db:"description,omitempty"`

		LoginUris pq.StringArray `db:"login_uris"`

		LogoutUris pq.StringArray `db:"logout_uris"`

		Name string `db:"name" rql:"filter"`

		Permissions pq.StringArray `db:"permissions"`

		RedirectUris pq.StringArray `db:"redirect_uris"`

		Type string `db:"type,omitempty"`

		CreatedAt strfmt.DateTime `db:"created_at,omitempty"`

		ID string `db:"id,omitempty" rql:"filter"`

		UpdatedAt strfmt.DateTime `db:"updated_at,omitempty"`

		TokenLifetime int64 `db:"token_lifetime"`
	}
)

// ApplicationCreate implements the teralytic.Backend interface
func (b *backend) ApplicationCreate(app *types.Application) error {

	clientID := uuid.Must(uuid.NewRandom())

	app.ClientID = base58.Encode(clientID[:])

	app.ClientSecret = funk.RandomString(32)

	out := &Application{}

	row := b.db.QueryRowx(
		`INSERT INTO applications 
		(name, description, type, client_id, client_secret, token_lifetime, login_uris, redirect_uris, logout_uris, allowed_grants, permissions)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) 
		ON CONFLICT(name) DO NOTHING RETURNING *`,
		app.Name,
		app.Description,
		app.Type,
		app.ClientID,
		app.ClientSecret,
		app.TokenLifetime,
		pq.StringArray(app.LoginUris),
		pq.StringArray(app.RedirectUris),
		pq.StringArray(app.LogoutUris),
		pq.StringArray(app.AllowedGrants),
		pq.StringArray(app.Permissions),
	)
	if err := row.StructScan(out); err != nil {
		if err == sql.ErrNoRows {
			return teralytic.ErrObjectExists
		}
		return err
	}

	*app = out.Application()

	return nil
}

// ApplicationGet gets an application
func (b *backend) ApplicationGet(query *rql.Query, app *types.Application) error {
	out := &Application{}

	parser := rql.MustNewParser(rql.Config{
		Model:            Application{},
		ColumnFn:         swag.ToFileName,
		ParamSymbol:      "$",
		PositionalParams: true,
	})

	params, err := parser.ParseQuery(query)
	if err != nil {
		return err
	}

	row := b.db.QueryRowx(
		`SELECT * FROM applications WHERE `+params.FilterExp,
		params.FilterArgs...)
	if err := row.StructScan(out); err != nil {
		return err
	}

	*app = out.Application()

	return nil
}

// ApplicationCreate implements the teralytic.Backend interface
func (b *backend) ApplicationUpdate(query *rql.Query, app *types.Application) error {
	out := &Application{}

	parser := rql.MustNewParser(rql.Config{
		Model:            Application{},
		ColumnFn:         swag.ToFileName,
		ParamSymbol:      "$",
		PositionalParams: true,
		ParamOffset:      10,
	})

	params, err := parser.ParseQuery(query)
	if err != nil {
		return err
	}

	args := []interface{}{
		app.Name,
		app.Description,
		app.Type,
		pq.StringArray(app.LoginUris),
		pq.StringArray(app.RedirectUris),
		pq.StringArray(app.LogoutUris),
		pq.StringArray(app.AllowedGrants),
		pq.StringArray(app.Permissions),
		app.TokenLifetime,
	}
	args = append(args, params.FilterArgs...)

	row := b.db.QueryRowx(
		`UPDATE applications SET
		name=$1, description=$2, type=$3, login_uris=$4, redirect_uris=$5, 
		logout_uris=$6, allowed_grants=$7, permissions=$8, token_lifetime=$9
		WHERE `+params.FilterExp+
			` RETURNING *`,
		args...)
	if err := row.StructScan(out); err != nil {
		if err == sql.ErrNoRows {
			return teralytic.ErrObjectExists
		}
		return err
	}

	*app = out.Application()

	return nil
}

// Application converts the backed application to an api types.Application
func (a *Application) Application() types.Application {
	return types.Application{
		ID: a.ID,

		Name: a.Name,

		Description: a.Description,

		Type: a.Type,

		ClientID: a.ClientID,

		ClientSecret: a.ClientSecret,

		TokenLifetime: a.TokenLifetime,

		LoginUris: a.LoginUris,

		RedirectUris: a.RedirectUris,

		LogoutUris: a.LogoutUris,

		AllowedGrants: a.AllowedGrants,

		Permissions: a.Permissions,

		CreatedAt: a.CreatedAt,

		UpdatedAt: a.UpdatedAt,
	}
}
