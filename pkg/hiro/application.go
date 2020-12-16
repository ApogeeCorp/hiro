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

package hiro

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/types"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/gosimple/slug"
)

type (
	// Application is the database model for an application
	Application struct {
		ID          types.ID         `json:"id" db:"id"`
		Name        string           `json:"name" db:"name"`
		Description *string          `json:"description,omitempty" db:"description"`
		Type        oauth.ClientType `json:"type" db:"type"`
		SecretKey   *string          `json:"secret_key,omitempty" db:"secret_key"`
		Permissions oauth.ScopeSet   `json:"permissions,omitempty" db:"-"`
		Grants      oauth.Grants     `json:"grants,omitempty" db:"-"`
		URIs        oauth.URIList    `json:"uris,omitempty" db:"uris"`
		CreatedAt   time.Time        `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time       `json:"updated_at,omitempty" db:"updated_at"`
		Metadata    types.Metadata   `json:"metadata,omitempty" db:"metadata"`
	}

	// ApplicationCreateInput is the application create request
	ApplicationCreateInput struct {
		Name        string           `json:"name"`
		Description *string          `json:"description,omitempty"`
		Type        oauth.ClientType `json:"type" db:"type"`
		Permissions oauth.ScopeSet   `json:"permissions,omitempty"`
		Grants      oauth.Grants     `json:"grants,omitempty"`
		URIs        oauth.URIList    `json:"uris,omitempty"`
		Metadata    types.Metadata   `json:"metadata,omitempty"`
	}

	// ApplicationUpdateInput is the application update request
	ApplicationUpdateInput struct {
		ApplicationID types.ID          `json:"id" structs:"-"`
		Name          *string           `json:"name" structs:"name,omitempty"`
		Description   *string           `json:"description,omitempty" structs:"description,omitempty"`
		Type          *oauth.ClientType `json:"type" structs:"type,omitempty"`
		Permissions   oauth.ScopeSet    `json:"permissions,omitempty" structs:"-"`
		Grants        oauth.Grants      `json:"grants,omitempty" structs:"-"`
		URIs          oauth.URIList     `json:"uris,omitempty" structs:"-"`
		Metadata      types.Metadata    `json:"metadata,omitempty" structs:"metadata,omitempty"`
	}

	// ApplicationGetInput is used to get an application for the id
	ApplicationGetInput struct {
		ApplicationID *types.ID `json:"application_id,omitempty"`
		Name          *string   `json:"name,omitempty"`
	}

	// ApplicationListInput is the application list request
	ApplicationListInput struct {
		Limit  *uint64 `json:"limit,omitempty"`
		Offset *uint64 `json:"offset,omitempty"`
	}

	// ApplicationDeleteInput is the application delete request input
	ApplicationDeleteInput struct {
		ApplicationID types.ID `json:"application_id"`
	}

	// ApplicationType defines an application type
	ApplicationType string

	applicationPatchInput struct {
		Application *Application
		Permissions oauth.ScopeSet
		Grants      oauth.Grants
	}
)

// ValidateWithContext handles validation of the ApplicationCreateInput struct
func (a ApplicationCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.Name, validation.Required, validation.Length(3, 64)),
		validation.Field(&a.Description, validation.NilOrNotEmpty),
		validation.Field(&a.Type, validation.Required),
		validation.Field(&a.Permissions, validation.NilOrNotEmpty),
		validation.Field(&a.Grants, validation.NilOrNotEmpty),
		validation.Field(&a.URIs, validation.NilOrNotEmpty),
	)
}

// ValidateWithContext handles validation of the ApplicationUpdateInput struct
func (a ApplicationUpdateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.ApplicationID, validation.Required),
		validation.Field(&a.Name, validation.NilOrNotEmpty, validation.Length(3, 64)),
		validation.Field(&a.Description, validation.NilOrNotEmpty),
		validation.Field(&a.Type, validation.NilOrNotEmpty),
		validation.Field(&a.Permissions, validation.NilOrNotEmpty),
		validation.Field(&a.Grants, validation.NilOrNotEmpty),
		validation.Field(&a.URIs, validation.NilOrNotEmpty),
	)
}

// ValidateWithContext handles validation of the ApplicationGetInput struct
func (a ApplicationGetInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.ApplicationID, validation.When(a.Name == nil, validation.Required).Else(validation.Nil)),
		validation.Field(&a.Name, validation.When(a.ApplicationID == nil, validation.Required).Else(validation.Nil)),
	)
}

// ValidateWithContext handles validation of the ApplicationListInput struct
func (a ApplicationListInput) ValidateWithContext(context.Context) error {
	return nil
}

// ValidateWithContext handles validation of the ApplicationDeleteInput
func (a ApplicationDeleteInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.ApplicationID, validation.Required),
	)
}

// ApplicationCreate create a new permission object
func (b *Backend) ApplicationCreate(ctx context.Context, params ApplicationCreateInput) (*Application, error) {
	var app Application

	log := api.Log(ctx).WithField("operation", "ApplicationCreate").WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("%w: failed to generate secret key", err)
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new application")

		stmt, args, err := sq.Insert("hiro.applications").
			Columns(
				"name",
				"description",
				"type",
				"secret_key",
				"uris",
				"metadata").
			Values(
				slug.Make(params.Name),
				null.String(params.Description),
				params.Type,
				hex.EncodeToString(key),
				params.URIs,
				null.JSON(params.Metadata),
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(`RETURNING *`).
			ToSql()
		if err != nil {
			log.Error(err.Error())

			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &app, stmt, args...); err != nil {
			log.Error(err.Error())

			return parseSQLError(err)
		}

		return b.applicationPatch(ctx, applicationPatchInput{&app, params.Permissions, params.Grants})
	}); err != nil {
		return nil, err
	}

	log.Debugf("application %s created", app.ID)

	return b.applicationPreload(ctx, app)
}

// ApplicationUpdate updates an application by id, including child objects
func (b *Backend) ApplicationUpdate(ctx context.Context, params ApplicationUpdateInput) (*Application, error) {
	var app Application

	log := api.Log(ctx).WithField("operation", "ApplicationUpdate").WithField("id", params.ApplicationID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating application")

		q := sq.Update("hiro.applications").
			PlaceholderFormat(sq.Dollar)

		updates := structs.Map(params)

		if len(params.Metadata) > 0 {
			updates["metadata"] = sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata)
		}

		if len(params.URIs) > 0 {
			updates["uris"] = params.URIs
		}

		if len(updates) > 0 {
			stmt, args, err := q.Where(sq.Eq{"id": params.ApplicationID}).
				SetMap(updates).
				Suffix("RETURNING *").
				ToSql()
			if err != nil {
				log.Error(err.Error())

				return fmt.Errorf("%w: failed to build query statement", err)
			}

			if err := tx.GetContext(ctx, &app, stmt, args...); err != nil {
				log.Error(err.Error())

				return parseSQLError(err)
			}
		} else {
			a, err := b.ApplicationGet(ctx, ApplicationGetInput{
				ApplicationID: &params.ApplicationID,
			})
			if err != nil {
				return err
			}
			app = *a
		}

		return b.applicationPatch(ctx, applicationPatchInput{&app, params.Permissions, params.Grants})
	}); err != nil {
		return nil, err
	}

	log.Debugf("application %s updated", app.Name)

	return b.applicationPreload(ctx, app)
}

// ApplicationGet gets an application by id and optionally preloads child objects
func (b *Backend) ApplicationGet(ctx context.Context, params ApplicationGetInput) (*Application, error) {
	var suffix string

	log := api.Log(ctx).WithField("operation", "ApplicationGet").
		WithField("id", params.ApplicationID).
		WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)

	if IsTransaction(db) {
		suffix = "FOR UPDATE"
	}

	query := sq.Select("*").
		From("hiro.applications").
		PlaceholderFormat(sq.Dollar)

	if params.ApplicationID != nil {
		query = query.Where(sq.Eq{"id": *params.ApplicationID})
	} else if params.Name != nil {
		query = query.Where(sq.Eq{"name": *params.Name})
	} else {
		return nil, fmt.Errorf("%w: application id or name required", ErrInputValidation)
	}

	stmt, args, err := query.
		Suffix(suffix).
		ToSql()
	if err != nil {
		log.Error(err.Error())

		return nil, parseSQLError(err)
	}

	app := Application{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(&app); err != nil {
		log.Error(err.Error())

		return nil, parseSQLError(err)
	}

	return b.applicationPreload(ctx, app)
}

// ApplicationList returns a listing of applications
func (b *Backend) ApplicationList(ctx context.Context, params ApplicationListInput) ([]*Application, error) {
	log := api.Log(ctx).WithField("operation", "ApplicationList")

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)

	query := sq.Select("*").
		From("hiro.applications")

	if params.Limit != nil {
		query = query.Limit(*params.Limit)
	}

	if params.Offset != nil {
		query = query.Offset(*params.Offset)
	}

	stmt, args, err := query.ToSql()
	if err != nil {
		return nil, err
	}

	apps := make([]*Application, 0)
	if err := db.SelectContext(ctx, &apps, stmt, args...); err != nil {
		return nil, parseSQLError(err)
	}

	for _, app := range apps {
		app, err = b.applicationPreload(ctx, *app)
		if err != nil {
			return nil, err
		}
	}

	return apps, nil
}

func (b *Backend) applicationPatch(ctx context.Context, params applicationPatchInput) error {
	log := api.Log(ctx).WithField("operation", "applicationPatch").WithField("application", params.Application.ID)

	db := b.DB(ctx)

	for audID, perms := range params.Permissions {
		if !types.ID(audID).Valid() {
			aud, err := b.AudienceGet(ctx, AudienceGetInput{
				Name: &audID,
			})
			if err != nil {
				err = fmt.Errorf("%w: lookup for audience named %s failed", err, audID)

				log.Error(err.Error())

				return err
			}

			audID = aud.ID.String()
		}

		if _, err := sq.Delete("hiro.application_permissions").
			Where(
				sq.Eq{"audience_id": types.ID(audID)},
				sq.Eq{"application_id": params.Application.ID},
			).
			PlaceholderFormat(sq.Dollar).
			RunWith(db).
			ExecContext(ctx); err != nil {
			log.Errorf("failed to delete permissions for audience: %s", audID, err)

			return parseSQLError(err)
		}

		for _, p := range perms {
			_, err := sq.Insert("hiro.application_permissions").
				Columns("application_id", "audience_id", "permission").
				Values(
					params.Application.ID,
					types.ID(audID),
					p,
				).
				Suffix("ON CONFLICT DO NOTHING").
				RunWith(db).
				PlaceholderFormat(sq.Dollar).
				ExecContext(ctx)
			if err != nil {
				log.Errorf("failed to update audience permissions %s: %s", audID, err)

				return parseSQLError(err)
			}
		}

		params.Application.Permissions = params.Permissions
	}

	for audID, grants := range params.Grants {
		if !types.ID(audID).Valid() {
			aud, err := b.AudienceGet(ctx, AudienceGetInput{
				Name: &audID,
			})
			if err != nil {
				err = fmt.Errorf("%w: lookup for audience named %s failed", err, audID)

				log.Error(err.Error())

				return err
			}

			audID = aud.ID.String()
		}

		if _, err := sq.Delete("hiro.application_grants").
			Where(
				sq.Eq{"audience_id": types.ID(audID)},
				sq.Eq{"application_id": params.Application.ID},
			).
			PlaceholderFormat(sq.Dollar).
			RunWith(db).
			ExecContext(ctx); err != nil {
			log.Errorf("failed to delete grants for audience: %s", audID, err)

			return parseSQLError(err)
		}

		for _, g := range grants {
			_, err := sq.Insert("hiro.application_grants").
				Columns("application_id", "audience_id", "grant_type").
				Values(
					params.Application.ID,
					types.ID(audID),
					g,
				).
				Suffix("ON CONFLICT DO NOTHING").
				RunWith(db).
				PlaceholderFormat(sq.Dollar).
				ExecContext(ctx)
			if err != nil {
				log.Errorf("failed to update audience grants %s: %s", audID, err)

				return parseSQLError(err)
			}
		}

		params.Application.Grants = params.Grants
	}

	return nil
}

func (b *Backend) applicationPreload(ctx context.Context, app Application) (*Application, error) {
	log := api.Log(ctx).WithField("operation", "applicationPreload").WithField("application", app.ID)

	db := b.DB(ctx)

	perms := []struct {
		Audience   string `db:"audience"`
		Permission string `db:"permission"`
	}{}

	if err := db.SelectContext(
		ctx,
		&perms,
		`SELECT a.name as audience, p.permission 
		 FROM hiro.application_permissions p
		 LEFT JOIN hiro.audiences a
		 	ON  a.id = p.audience_id
		 WHERE p.application_id=$1`,
		app.ID); err != nil {
		log.Errorf("failed to load application permissions %s: %s", app.ID, err)

		return nil, parseSQLError(err)
	}

	app.Permissions = make(oauth.ScopeSet)
	for _, p := range perms {
		app.Permissions.Append(p.Audience, p.Permission)
	}

	grants := []struct {
		Audience string          `db:"audience"`
		Grant    oauth.GrantType `db:"grant_type"`
	}{}

	if err := db.SelectContext(
		ctx,
		&grants,
		`SELECT a.name as audience, g.grant_type 
		 FROM hiro.application_grants g
		 LEFT JOIN hiro.audiences a
		 	ON  a.id = g.audience_id
		 WHERE g.application_id=$1`,
		app.ID); err != nil {
		log.Errorf("failed to load application grants %s: %s", app.ID, err)

		return nil, parseSQLError(err)
	}

	app.Grants = make(oauth.Grants)
	for _, g := range grants {
		app.Grants.Append(g.Audience, g.Grant)
	}

	return &app, nil
}

// ApplicationDelete deletes an application by id
func (b *Backend) ApplicationDelete(ctx context.Context, params ApplicationDeleteInput) error {
	log := api.Log(ctx).WithField("operation", "ApplicationDelete").WithField("application", params.ApplicationID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)
	if _, err := sq.Delete("hiro.applications").
		Where(
			sq.Eq{"id": params.ApplicationID},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to delete application %s: %s", params.ApplicationID, err)
		return parseSQLError(err)
	}

	return nil
}
