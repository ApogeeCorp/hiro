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
		ID            ID                    `json:"id" db:"id"`
		DomainID      ID                    `json:"domain_id" db:"domain_id"`
		Name          string                `json:"name" db:"name"`
		Slug          string                `json:"slug" db:"slug"`
		Description   *string               `json:"description,omitempty" db:"description"`
		Type          oauth.ClientType      `json:"type" db:"type"`
		ClientID      *string               `json:"client_id,omitempty" db:"client_id"`
		ClientSecret  *string               `json:"client_secret,omitempty" db:"client_secret"`
		TokenSecretID *ID                   `json:"token_secret_id,omitempty" db:"token_secret_id"`
		TokenSecret   *Secret               `json:"-" db:"-"`
		Permissions   []Permission          `json:"permissions,omitempty" db:"-"`
		Grants        []ApplicationGrant    `json:"grants,omitempty" db:"-"`
		Endpoints     []ApplicationEndpoint `json:"uris,omitempty" db:"-"`
		CreatedAt     time.Time             `json:"created_at" db:"created_at"`
		UpdatedAt     *time.Time            `json:"updated_at,omitempty" db:"updated_at"`
		Metadata      common.Map            `json:"metadata,omitempty" db:"metadata"`
		Domain        *Domain               `json:"domain,omitempty" db:"-"`
	}

	// ApplicationGrant is an application grant entry
	ApplicationGrant struct {
		InstanceID ID              `json:"instance_id"`
		Type       oauth.GrantType `json:"grant_type"`
	}

	// ApplicationEndpoint is an application uri
	ApplicationEndpoint struct {
		InstanceID ID                      `json:"instance_id"`
		URI        string                  `json:"uri"`
		Type       ApplicationEndpointType `json:"type"`
	}

	// ApplicationEndpointType is an application uri type
	ApplicationEndpointType string

	// ApplicationCreateInput is the application create request
	ApplicationCreateInput struct {
		InstanceID    ID                    `json:"instance_id"`
		Name          string                `json:"name"`
		Description   *string               `json:"description,omitempty"`
		Type          oauth.ClientType      `json:"type"`
		TokenSecretID *ID                   `json:"token_secret_id,omitempty"`
		Permissions   []Permission          `json:"permissions,omitempty"`
		Grants        []ApplicationGrant    `json:"grants,omitempty"`
		Endpoints     []ApplicationEndpoint `json:"uris,omitempty"`
		Metadata      common.Map            `json:"metadata,omitempty"`
	}

	// ApplicationUpdateInput is the application update request
	ApplicationUpdateInput struct {
		ApplicationID ID                `json:"id" structs:"-"`
		InstanceID    ID                `json:"instance_id" db:"instance_id"`
		Name          *string           `json:"name" structs:"name,omitempty"`
		Description   *string           `json:"description,omitempty" structs:"description,omitempty"`
		Type          *oauth.ClientType `json:"type" structs:"type,omitempty"`
		TokenSecretID *ID               `json:"token_secret_id,omitempty" structs:"token_secret_id,omitempty"`
		Permissions   PermissionUpdate  `json:"permissions,omitempty" structs:"-"`
		Grants        GrantUpdate       `json:"grants,omitempty" structs:"-"`
		Endpoints     EndpointUpdate    `json:"uris,omitempty" structs:"-"`
		Metadata      common.Map        `json:"metadata,omitempty" structs:"metadata,omitempty"`
	}

	// PermissionUpdate is used to modify application permissions
	PermissionUpdate struct {
		Add    []Permission `json:"add,omitempty"`
		Remove []Permission `json:"remove,omitempty"`
	}

	// GrantUpdate is used to modify application grants
	GrantUpdate struct {
		Add    []ApplicationGrant `json:"add,omitempty"`
		Remove []ApplicationGrant `json:"remove,omitempty"`
	}

	// EndpointUpdate is used to modify application URIs
	EndpointUpdate struct {
		Add    []ApplicationEndpoint `json:"add,omitempty"`
		Remove []ApplicationEndpoint `json:"remove,omitempty"`
	}

	// ApplicationGetInput is used to get an application for the id
	ApplicationGetInput struct {
		DomainID      ID                 `json:"-"`
		ApplicationID *ID                `json:"application_id,omitempty"`
		Expand        common.StringSlice `json:"expand,omitempty"`
		ClientID      *string            `json:"-"`
		Name          *string            `json:"-"`
	}

	// ApplicationListInput is the application list request
	ApplicationListInput struct {
		DomainID ID                 `json:"-"`
		Expand   common.StringSlice `json:"expand,omitempty"`
		Limit    *uint64            `json:"limit,omitempty"`
		Offset   *uint64            `json:"offset,omitempty"`
		Count    *uint64            `json:"count,omitempty"`
	}

	// ApplicationDeleteInput is the application delete request input
	ApplicationDeleteInput struct {
		DomainID      ID `json:"instance_id" db:"instance_id"`
		ApplicationID ID `json:"application_id"`
	}

	// ApplicationType defines an application type
	ApplicationType string

	applicationPatchInput struct {
		Application *Application
		Permissions PermissionUpdate
		Grants      GrantUpdate
		Endpoints   EndpointUpdate
	}
)

const (
	ApplicationEndpointTypeApp      ApplicationEndpointType = "application"
	ApplicationEndpointTypeRedirect ApplicationEndpointType = "redirect"
)

// ValidateWithContext handles validation of the ApplicationCreateInput struct
func (a ApplicationCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.Name, validation.Required, validation.Length(3, 64)),
		validation.Field(&a.Description, validation.NilOrNotEmpty),
		validation.Field(&a.Type, validation.Required),
		validation.Field(&a.TokenSecretID, validation.Required),
		validation.Field(&a.Permissions, validation.NilOrNotEmpty),
		validation.Field(&a.Grants, validation.NilOrNotEmpty),
		validation.Field(&a.Endpoints, validation.NilOrNotEmpty),
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
		validation.Field(&a.Endpoints, validation.NilOrNotEmpty),
	)
}

// ValidateWithContext handles validation of the ApplicationGetInput struct
func (a ApplicationGetInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.DomainID, validation.Required),
		validation.Field(&a.ApplicationID, validation.When(a.Name == nil, validation.Required).Else(validation.Empty)),
		validation.Field(&a.Name, validation.When(!a.ApplicationID.Valid(), validation.Required).Else(validation.Nil)),
	)
}

// ValidateWithContext handles validation of the ApplicationListInput struct
func (a ApplicationListInput) ValidateWithContext(context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.DomainID, validation.Required),
	)
}

// ValidateWithContext handles validation of the ApplicationDeleteInput
func (a ApplicationDeleteInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.DomainID, validation.Required),
		validation.Field(&a.ApplicationID, validation.Required),
	)
}

// ApplicationCreate create a new permission object
func (h *Hiro) ApplicationCreate(ctx context.Context, params ApplicationCreateInput) (*Application, error) {
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

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		stmt, args, err := sq.Insert("hiro.applications").
			Columns(
				"instance_id",
				"name",
				"description",
				"type",
				"token_secret_id",
				"client_id",
				"client_secret",
				"uris",
				"metadata").
			Values(
				params.InstanceID,
				params.Name,
				null.String(params.Description),
				params.Type,
				params.TokenSecretID,
				NewID().String(),
				hex.EncodeToString(key),
				params.Endpoints,
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

		return nil
	}); err != nil {
		if errors.Is(err, ErrDuplicateObject) {
			return h.ApplicationGet(ctx, ApplicationGetInput{
				Name: &params.Name,
			})
		}
		log.Error(err.Error())

		return nil, err
	}

	log.Debugf("application %s created", app.ID)

	return h.applicationExpand(ctx, &app, ExpandAll)
}

// ApplicationUpdate updates an application by id, including child objects
func (h *Hiro) ApplicationUpdate(ctx context.Context, params ApplicationUpdateInput) (*Application, error) {
	var app Application

	log := Log(ctx).WithField("operation", "ApplicationUpdate").WithField("id", params.ApplicationID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating application")

		updates := structs.Map(params)

		if params.Metadata != nil {
			updates["metadata"] = sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata)
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
			a, err := h.ApplicationGet(ctx, ApplicationGetInput{
				DomainID:      params.InstanceID,
				ApplicationID: &params.ApplicationID,
			})
			if err != nil {
				return err
			}
			app = *a
		}

		return nil
	}); err != nil {
		return nil, err
	}

	log.Debugf("application %s updated", app.Name)

	return h.applicationExpand(ctx, &app, ExpandAll)
}

// ApplicationGet gets an application by id and optionally preloads child objects
func (h *Hiro) ApplicationGet(ctx context.Context, params ApplicationGetInput) (*Application, error) {
	var suffix string

	log := Log(ctx).WithField("operation", "ApplicationGet").
		WithField("id", params.ApplicationID).
		WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

	query := sq.Select("*").
		From("hiro.applications").
		PlaceholderFormat(sq.Dollar).
		Where(sq.Eq{"instance_id": params.DomainID})

	if params.ApplicationID != nil {
		query = query.Where(sq.Eq{"id": params.ApplicationID})
	} else if params.ClientID != nil {
		query = query.Where(sq.Eq{"client_id": params.ClientID})
	} else if params.Name != nil {
		query = query.Where(sq.Or{
			sq.Eq{"name": *params.Name},
			sq.Eq{"slug": *params.Name},
		})
	} else {
		return nil, fmt.Errorf("%w: application id, client id, or name required", ErrInputValidation)
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

	return h.applicationExpand(ctx, &app, params.Expand)
}

// ApplicationList returns a listing of applications
func (h *Hiro) ApplicationList(ctx context.Context, params ApplicationListInput) ([]*Application, error) {
	log := Log(ctx).WithField("operation", "ApplicationList")

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

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
		if _, err = h.applicationExpand(ctx, app, params.Expand); err != nil {
			return nil, err
		}
	}

	return apps, nil
}

// ApplicationDelete deletes an application by id
func (h *Hiro) ApplicationDelete(ctx context.Context, params ApplicationDeleteInput) error {
	log := Log(ctx).WithField("operation", "ApplicationDelete").WithField("application", params.ApplicationID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)
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

func (h *Hiro) applicationExpand(ctx context.Context, app *Application, expand common.StringSlice) (*Application, error) {
	log := Log(ctx).WithField("operation", "applicationExpand").WithField("application", app.ID)

	db := h.DB(ctx)

	if expand.ContainsAny("permissions", "*") {
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
	}

	if expand.ContainsAny("grants", "*") {
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
	}

	if expand.ContainsAny("endpoints", "*") {
		if err := db.SelectContext(
			ctx,
			&app.Endpoints,
			`SELECT instance_id, uri, uri_type 
			FROM hiro.application_uris 
			WHERE application_id=$1`,
			app.ID); err != nil {
			log.Errorf("failed to load application uris %s: %s", app.ID, err)

			return nil, ParseSQLError(err)
		}
	}

	if app.TokenSecretID != nil {
		if err := db.SelectContext(
			ctx,
			&app.TokenSecret,
			`SELECT * 
			FROM hiro.secrets 
			WHERE id=$1`,
			app.TokenSecretID); err != nil {
			log.Errorf("failed to load application secret %s: %s", app.ID, err)

			return nil, ParseSQLError(err)
		}
	}

	return app, nil
}
