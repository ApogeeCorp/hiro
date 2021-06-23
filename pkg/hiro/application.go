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
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"

	"github.com/ModelRocket/hiro/pkg/common"
	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// ApplicationController is the applications API interface
	ApplicationController interface {
		ApplicationCreate(ctx context.Context, params ApplicationCreateInput) (*Application, error)
		ApplicationGet(ctx context.Context, params ApplicationGetInput) (*Application, error)
		ApplicationList(ctx context.Context, params ApplicationListInput) ([]*Application, error)
		ApplicationUpdate(ctx context.Context, params ApplicationUpdateInput) (*Application, error)
		ApplicationDelete(ctx context.Context, params ApplicationDeleteInput) error
	}

	// Application is the database model for an application
	Application struct {
		ID          ID                      `json:"id" db:"id"`
		InstanceID  ID                      `json:"instance_id" db:"instance_id"`
		Name        string                  `json:"name" db:"name"`
		Slug        string                  `json:"slug" db:"slug"`
		Description *string                 `json:"description,omitempty" db:"description"`
		Type        oauth.ClientType        `json:"type" db:"type"`
		SecretKey   *string                 `json:"secret_key,omitempty" db:"secret_key"`
		Permissions []ApplicationPermission `json:"permissions,omitempty" db:"-"`
		Grants      []ApplicationGrant      `json:"grants,omitempty" db:"-"`
		URIs        []ApplicationURI        `json:"uris,omitempty" db:"-"`
		CreatedAt   time.Time               `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time              `json:"updated_at,omitempty" db:"updated_at"`
		Metadata    common.Map              `json:"metadata,omitempty" db:"metadata"`
	}

	// ApplicationPermission is an application permission entry
	ApplicationPermission struct {
		InstanceID ID     `json:"instance_id"`
		Permission string `json:"permission"`
	}

	// ApplicationGrant is an application grant entry
	ApplicationGrant struct {
		InstanceID ID              `json:"instance_id"`
		GrantType  oauth.GrantType `json:"grant_type"`
	}

	ApplicationURI struct {
		InstanceID ID        `json:"instance_id"`
		URI        oauth.URI `json:"uri"`
	}

	// ApplicationCreateInput is the application create request
	ApplicationCreateInput struct {
		InstanceID  ID                      `json:"instance_id"`
		Name        string                  `json:"name"`
		Description *string                 `json:"description,omitempty"`
		Type        oauth.ClientType        `json:"type"`
		Permissions []ApplicationPermission `json:"permissions,omitempty" db:"-"`
		Grants      []ApplicationGrant      `json:"grants,omitempty" db:"-"`
		URIs        []ApplicationURI        `json:"uris,omitempty" db:"-"`
		Metadata    common.Map              `json:"metadata,omitempty"`
	}

	// ApplicationUpdateInput is the application update request
	ApplicationUpdateInput struct {
		ApplicationID ID                 `json:"id" structs:"-"`
		InstanceID    ID                 `json:"instance_id" db:"instance_id"`
		Name          *string            `json:"name" structs:"name,omitempty"`
		Description   *string            `json:"description,omitempty" structs:"description,omitempty"`
		Type          *oauth.ClientType  `json:"type" structs:"type,omitempty"`
		Permissions   PermissionUpdate  `json:"permissions,omitempty" structs:"-"`
		Grants        []ApplicationGrant `json:"grants,omitempty" structs:"-"`
		URIs          []ApplicationURI   `json:"uris,omitempty" structs:"-"`
		Metadata      common.Map         `json:"metadata,omitempty" structs:"metadata,omitempty"`
	}

	// PermissionUpdate is used to modify application permissions
	PermissionUpdate struct {
		Add    []ApplicationPermission `json:"add,omitempty"`
		Remove []ApplicationPermission `json:"remove,omitempty"`
	}

	// GrantUpdate is used to modify application grants
	GrantUpdate struct {
		Add []ApplicationGrant `json:"add,omitempty"`
		Remove []ApplicationGrat `json:"remove,omitempty"`
	}

		// URIUpdate is used to modify application URIs
		GrantUpdate struct {
			Add []ApplicationGrant `json:"add,omitempty"`
			Remove []ApplicationGrat `json:"remove,omitempty"`
		}

	// ApplicationGetInput is used to get an application for the id
	ApplicationGetInput struct {
		InstanceID    ID      `json:"instance_id,omitempty"`
		ApplicationID ID      `json:"application_id,omitempty"`
		Name          *string `json:"name,omitempty"`
	}

	// ApplicationListInput is the application list request
	ApplicationListInput struct {
		InstanceID ID      `json:"instance_id" db:"instance_id"`
		Limit      *uint64 `json:"limit,omitempty"`
		Offset     *uint64 `json:"offset,omitempty"`
		Count      *uint64 `json:"count,omitempty"`
	}

	// ApplicationDeleteInput is the application delete request input
	ApplicationDeleteInput struct {
		InstanceID    ID `json:"instance_id" db:"instance_id"`
		ApplicationID ID `json:"application_id"`
	}

	// ApplicationType defines an application type
	ApplicationType string

	applicationPatchInput struct {
		Application *Application
		Permissions PermissionUpdate
		Grants      GrantUpdate
	}
)

// ValidateWithContext handles validation of the ApplicationCreateInput struct
func (a ApplicationCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.InstanceID, validation.Required),
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
		validation.Field(&a.InstanceID, validation.Required),
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
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.ApplicationID, validation.When(a.Name == nil, validation.Required).Else(validation.Empty)),
		validation.Field(&a.Name, validation.When(!a.ApplicationID.Valid(), validation.Required).Else(validation.Nil)),
	)
}

// ValidateWithContext handles validation of the ApplicationListInput struct
func (a ApplicationListInput) ValidateWithContext(context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.InstanceID, validation.Required),
	)
}

// ValidateWithContext handles validation of the ApplicationDeleteInput
func (a ApplicationDeleteInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.ApplicationID, validation.Required),
	)
}

// ApplicationCreate create a new permission object
func (b *Hiro) ApplicationCreate(ctx context.Context, params ApplicationCreateInput) (*Application, error) {
	var app Application

	log := Log(ctx).WithField("operation", "ApplicationCreate").WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("%w: failed to generate secret key", err)
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		stmt, args, err := sq.Insert("hiro.applications").
			Columns(
				"instance_id",
				"name",
				"description",
				"type",
				"secret_key",
				"uris",
				"metadata").
			Values(
				params.InstanceID,
				params.Name,
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
			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &app, stmt, args...); err != nil {
			return ParseSQLError(err)

		}

		return b.applicationPatch(ctx, applicationPatchInput{&app, PermissionUpdate{Add: params.Permissions}, params.Grants})
	}); err != nil {
		if errors.Is(err, ErrDuplicateObject) {
			return b.ApplicationGet(ctx, ApplicationGetInput{
				Name: &params.Name,
			})
		}
		log.Error(err.Error())

		return nil, err
	}

	log.Debugf("application %s created", app.ID)

	return b.applicationPreload(ctx, &app)
}

// ApplicationUpdate updates an application by id, including child objects
func (b *Hiro) ApplicationUpdate(ctx context.Context, params ApplicationUpdateInput) (*Application, error) {
	var app Application

	log := Log(ctx).WithField("operation", "ApplicationUpdate").WithField("id", params.ApplicationID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating application")

		updates := structs.Map(params)

		if params.Metadata != nil {
			updates["metadata"] = sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata)
		}

		if len(params.URIs) > 0 {
			updates["uris"] = params.URIs
		}

		if len(updates) > 0 {
			if _, err := sq.Select("id").
				From("hiro.applications").
				Where(sq.Eq{
					"instance_id": params.InstanceID,
					"id":          params.ApplicationID,
				}).
				Suffix("FOR UPDATE").
				RunWith(tx).
				ExecContext(ctx); err != nil {
				return ParseSQLError(err)
			}

			stmt, args, err := sq.Update("hiro.applications").
				PlaceholderFormat(sq.Dollar).
				Where(sq.Eq{
					"instance_id": params.InstanceID,
					"id":          params.ApplicationID,
				}).SetMap(updates).
				Suffix("RETURNING *").
				ToSql()
			if err != nil {
				log.Error(err.Error())

				return fmt.Errorf("%w: failed to build query statement", err)
			}

			if err := tx.GetContext(ctx, &app, stmt, args...); err != nil {
				log.Error(err.Error())

				return ParseSQLError(err)
			}
		} else {
			a, err := b.ApplicationGet(ctx, ApplicationGetInput{
				InstanceID:    params.InstanceID,
				ApplicationID: params.ApplicationID,
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

	return b.applicationPreload(ctx, &app)
}

// ApplicationGet gets an application by id and optionally preloads child objects
func (b *Hiro) ApplicationGet(ctx context.Context, params ApplicationGetInput) (*Application, error) {
	var suffix string

	log := Log(ctx).WithField("operation", "ApplicationGet").
		WithField("id", params.ApplicationID).
		WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)

	query := sq.Select("*").
		From("hiro.applications").
		PlaceholderFormat(sq.Dollar)

	if params.ApplicationID.Valid() {
		query = query.Where(sq.Eq{"id": params.ApplicationID})
	} else if params.Name != nil {
		query = query.Where(sq.Or{
			sq.Eq{"name": *params.Name},
			sq.Eq{"slug": *params.Name},
		})
	} else {
		return nil, fmt.Errorf("%w: application id or name required", ErrInputValidation)
	}

	stmt, args, err := query.
		Suffix(suffix).
		ToSql()
	if err != nil {
		log.Error(err.Error())

		return nil, ParseSQLError(err)
	}

	app := Application{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(&app); err != nil {
		log.Error(err.Error())

		return nil, ParseSQLError(err)
	}

	return b.applicationPreload(ctx, &app)
}

// ApplicationList returns a listing of applications
func (b *Hiro) ApplicationList(ctx context.Context, params ApplicationListInput) ([]*Application, error) {
	log := Log(ctx).WithField("operation", "ApplicationList")

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)

	target := "*"
	if params.Count != nil {
		target = "COUNT(*)"
	}

	query := sq.Select(target).
		From("hiro.applications")

	if safe.Uint64(params.Limit) > 0 {
		query = query.Limit(*params.Limit)
	}

	if safe.Uint64(params.Offset) > 0 {
		query = query.Offset(*params.Offset)
	}

	stmt, args, err := query.ToSql()
	if err != nil {
		return nil, err
	}

	if params.Count != nil {
		if err := db.GetContext(ctx, params.Count, stmt, args...); err != nil {
			return nil, ParseSQLError(err)
		}

		return nil, nil
	}

	apps := make([]*Application, 0)
	if err := db.SelectContext(ctx, &apps, stmt, args...); err != nil {
		return nil, ParseSQLError(err)
	}

	for _, app := range apps {
		if _, err = b.applicationPreload(ctx, app); err != nil {
			return nil, err
		}
	}

	return apps, nil
}

// ApplicationDelete deletes an application by id
func (b *Hiro) ApplicationDelete(ctx context.Context, params ApplicationDeleteInput) error {
	log := Log(ctx).WithField("operation", "ApplicationDelete").WithField("application", params.ApplicationID)

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
		return ParseSQLError(err)
	}

	return nil
}

func (b *Hiro) applicationPatch(ctx context.Context, params applicationPatchInput) error {
	log := Log(ctx).WithField("operation", "applicationPatch").WithField("application", params.Application.ID)

	db := b.DB(ctx)

	for _, p := range params.Permissions.Add {
		_, err := sq.Insert("hiro.application_permissions").
			Columns("application_id", "instance_id", "permission").
			Values(
				params.Application.ID,
				p.InstanceID,
				p.Permission,
			).
			Suffix("ON CONFLICT DO NOTHING").
			RunWith(db).
			PlaceholderFormat(sq.Dollar).
			ExecContext(ctx)
		if err != nil {
			log.Errorf("failed to update permissions for application %s: %s", params.Application.ID, err)

			return ParseSQLError(err)
		}
	}

	for _, p := range params.Permissions.Remove {
		if _, err := sq.Delete("hiro.application_permissions").
			Where(
				sq.Eq{
					"instance_id":   p.InstanceID,
					"application_id": params.Application.ID,
					"permission":     p,
				}).
			PlaceholderFormat(sq.Dollar).
			RunWith(db).
			ExecContext(ctx); err != nil {
			log.Errorf("failed to delete permissions for application: %s", params.Application.ID, err)

			return ParseSQLError(err)
		}
	}

	for _, g := range params.Grants {
		
		if _, err := sq.Delete("hiro.application_grants").
			Where(
				sq.Eq{"instance_id": g.},
				sq.Eq{"application_id": params.Application.ID},
			).
			PlaceholderFormat(sq.Dollar).
			RunWith(db).
			ExecContext(ctx); err != nil {
			log.Errorf("failed to delete grants for instance: %s", audID, err)

			return ParseSQLError(err)
		}

		for _, g := range grants {
			_, err := sq.Insert("hiro.application_grants").
				Columns("application_id", "instance_id", "grant_type").
				Values(
					params.Application.ID,
					ID(audID),
					g,
				).
				Suffix("ON CONFLICT DO NOTHING").
				RunWith(db).
				PlaceholderFormat(sq.Dollar).
				ExecContext(ctx)
			if err != nil {
				log.Errorf("failed to update instance grants %s: %s", audID, err)

				return ParseSQLError(err)
			}
		}

		params.Application.Grants = params.Grants
	}

	return nil
}

func (b *Hiro) applicationPreload(ctx context.Context, app *Application) (*Application, error) {
	log := Log(ctx).WithField("operation", "applicationPreload").WithField("application", app.ID)

	db := b.DB(ctx)

	if err := db.SelectContext(
		ctx,
		&app.Permissions,
		`SELECT instance_id, permission
		 FROM hiro.application_permissions
		 WHERE application_id=$1`,
		app.ID); err != nil {
		log.Errorf("failed to load application permissions %s: %s", app.ID, err)

		return nil, ParseSQLError(err)
	}

	if err := db.SelectContext(
		ctx,
		&app.Grants,
		`SELECT instance_id, grant_type 
		 FROM hiro.application_grants 
		 WHERE application_id=$1`,
		app.ID); err != nil {
		log.Errorf("failed to load application grants %s: %s", app.ID, err)

		return nil, ParseSQLError(err)
	}

	return app, nil
}
