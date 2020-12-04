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
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/gosimple/slug"
	"github.com/lib/pq"
)

type (
	// Application is the database model for an application
	Application struct {
		ID          types.ID          `json:"id" db:"id"`
		Name        string            `json:"name" db:"name"`
		Description *string           `json:"description,omitempty" db:"description"`
		Type        oauth.ClientType  `json:"type" db:"type"`
		SecretKey   *string           `json:"secret_key,omitempty" db:"secret_key"`
		Permissions oauth.Permissions `json:"permissions,omitempty" db:"permissions"`
		Grants      oauth.Grants      `json:"grants,omitempty" db:"grants"`
		URIs        pq.StringArray    `json:"uris,omitempty" db:"uris"`
		CreatedAt   time.Time         `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time        `json:"updated_at,omitempty" db:"updated_at"`
		Metadata    types.Metadata    `json:"metadata,omitempty" db:"metadata"`
	}

	// ApplicationCreateInput is the application create request
	ApplicationCreateInput struct {
		Name        string            `json:"name"`
		Description *string           `json:"description,omitempty"`
		Type        oauth.ClientType  `json:"type" db:"type"`
		Permissions oauth.Permissions `json:"permissions,omitempty"`
		Grants      oauth.Grants      `json:"grants,omitempty"`
		URIs        []string          `json:"uris,omitempty"`
		Metadata    types.Metadata    `json:"metadata,omitempty"`
	}

	// ApplicationUpdateInput is the application update request
	ApplicationUpdateInput struct {
		ApplicationID types.ID          `json:"id" structs:"-"`
		Name          *string           `json:"name" structs:"name,omitempty"`
		Description   *string           `json:"description,omitempty" structs:"description,omitempty"`
		Type          *oauth.ClientType `json:"type" structs:"type,omitempty"`
		Permissions   oauth.Permissions `json:"permissions,omitempty" structs:"permissions,omitempty"`
		Grants        oauth.Grants      `json:"grants,omitempty" structs:"grants,omitempty"`
		URIs          []string          `json:"uris,omitempty" structs:"uris,omitempty"`
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
)

// ValidateWithContext handles validation of the ApplicationCreateInput struct
func (a ApplicationCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.Name, validation.Required, validation.Length(3, 64)),
		validation.Field(&a.Description, validation.NilOrNotEmpty),
		validation.Field(&a.Type, validation.Required),
		validation.Field(&a.Permissions, validation.NilOrNotEmpty),
		validation.Field(&a.Grants, validation.NilOrNotEmpty),
		validation.Field(&a.URIs, validation.NilOrNotEmpty, validation.Each(is.RequestURI)),
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
		validation.Field(&a.URIs, validation.NilOrNotEmpty, validation.Each(is.RequestURI)),
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
func (h *Hiro) ApplicationCreate(ctx context.Context, params ApplicationCreateInput) (*Application, error) {
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

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new application")

		stmt, args, err := sq.Insert("hiro.applications").
			Columns(
				"name",
				"description",
				"type",
				"secret_key",
				"permissions",
				"grants",
				"uris",
				"metadata").
			Values(
				slug.Make(params.Name),
				null.String(params.Description),
				params.Type,
				hex.EncodeToString(key),
				params.Permissions,
				params.Grants,
				pq.Array(params.URIs),
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

		return nil
	}); err != nil {
		return nil, err
	}

	log.Debugf("application %s created", app.ID)

	return &app, nil
}

// ApplicationUpdate updates an application by id, including child objects
func (h *Hiro) ApplicationUpdate(ctx context.Context, params ApplicationUpdateInput) (*Application, error) {
	var app Application

	log := api.Log(ctx).WithField("operation", "ApplicationUpdate").WithField("id", params.ApplicationID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating application")

		q := sq.Update("hiro.applications").
			PlaceholderFormat(sq.Dollar)

		updates := structs.Map(params)

		if _, ok := updates["metadata"]; ok {
			updates["metadata"] = sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata)
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
		}

		return nil
	}); err != nil {
		return nil, err
	}

	log.Debugf("application %s updated", app.Name)

	return &app, nil
}

// ApplicationGet gets an application by id and optionally preloads child objects
func (h *Hiro) ApplicationGet(ctx context.Context, params ApplicationGetInput) (*Application, error) {
	var suffix string

	log := api.Log(ctx).WithField("operation", "ApplicationGet").
		WithField("id", params.ApplicationID).
		WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

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

	app := &Application{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(app); err != nil {
		log.Error(err.Error())

		return nil, parseSQLError(err)
	}

	return app, nil
}

// ApplicationList returns a listing of applications
func (h *Hiro) ApplicationList(ctx context.Context, params ApplicationListInput) ([]*Application, error) {
	log := api.Log(ctx).WithField("operation", "ApplicationList")

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

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

	return apps, nil
}

// ApplicationDelete deletes an application by id
func (h *Hiro) ApplicationDelete(ctx context.Context, params ApplicationDeleteInput) error {
	log := api.Log(ctx).WithField("operation", "ApplicationDelete").WithField("article", params.ApplicationID)

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
		return parseSQLError(err)
	}

	return nil
}
