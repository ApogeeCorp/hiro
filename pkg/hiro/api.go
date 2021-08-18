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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/ModelRocket/hiro/api/swagger"
	"github.com/ModelRocket/hiro/pkg/common"
	"github.com/ghodss/yaml"
	"github.com/go-openapi/loads"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// APIController is the API management interface
	APIController interface {
		APICreate(ctx context.Context, params APICreateParams) (*API, error)
		APIImport(ctx context.Context, params APIImportParams) (*API, error)
		APIGet(ctx context.Context, params APIGetParams) (*API, error)
	}

	// API defines an api specification managed by hiro
	API struct {
		ID          ID              `json:"id" db:"id"`
		Name        string          `json:"name" db:"name"`
		Version     string          `json:"version" db:"version"`
		Description *string         `json:"description,omitempty" db:"description"`
		Spec        json.RawMessage `json:"spec,omitempty" db:"spec"`
		CreatedAt   time.Time       `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time      `json:"updated_at,omitempty" db:"updated_at"`
		Permissions []Permission    `json:"permissions,omitempty" db:"-"`
		Metadata    common.Map      `json:"metadata,omitempty" db:"metadata"`
	}

	// APICreateParams is the input for APICreate
	APICreateParams struct {
		Params
		Name        string                  `json:"name"`
		Version     string                  `json:"version"`
		Description *string                 `json:"description,omitempty"`
		Spec        json.RawMessage         `json:"spec"`
		Permissions []PermissionCreateInput `json:"permissions,omitempty"`
	}

	// APIImportParams is the input for APIImport
	APIImportParams struct {
		Params
		Spec string `json:"spec"`
	}

	// APIGetParams is the input for APIGet
	APIGetParams struct {
		Params
		ID      *ID     `json:"id,omitempty"`
		Name    *string `json:"name,omitempty"`
		Version *string `json:"version,omitempty"`
	}
)

// ValidateWithContext validates the APICreateInput type
func (p APICreateParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Name, validation.Required),
		validation.Field(&p.Version, validation.Required, is.Semver),
		validation.Field(&p.Description, validation.NilOrNotEmpty),
		validation.Field(&p.Spec, validation.Required),
		validation.Field(&p.Permissions, validation.NilOrNotEmpty),
	)
}

// APICreate creates a new api
func (h *Hiro) APICreate(ctx context.Context, params APICreateParams) (*API, error) {
	var api API

	log := Log(ctx).
		WithField("operation", "APICreate").
		WithField("name", fmt.Sprintf("%s/%s", params.Name, params.Version))

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new api")

		stmt, args, err := sq.Insert("hiro.apis").
			Columns(
				"name",
				"version",
				"description",
				"spec",
			).
			Values(
				params.Name,
				params.Version,
				params.Description,
				params.Spec,
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(
				`ON CONFLICT ON CONSTRAINT api_version DO UPDATE SET description=$5, spec=$6 RETURNING *`,
				params.Description,
				params.Spec,
			).
			ToSql()
		if err != nil {
			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &api, stmt, args...); err != nil {
			return ParseSQLError(err)
		}

		// create any necessary permissions
		for _, p := range params.Permissions {
			p.ApiID = api.ID

			if _, err := h.PermissionCreate(ctx, p); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		log.Error(err.Error())

		return nil, err
	}

	log.Debugf("api %s created", api.ID)

	return &api, nil
}

// ValidateWithContext validates the APICreateInput type
func (p APIImportParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Spec, validation.Required, is.JSON),
	)
}

// APIImport imports an api definition
func (h *Hiro) APIImport(ctx context.Context, params APIImportParams) (*API, error) {
	// intialize the hiro api
	doc, err := loads.Analyzed(swagger.HiroSwaggerSpec, "")
	if err != nil {
		return nil, fmt.Errorf("failed to load swagger document: %w", err)
	}
	info := doc.Spec().Info

	spec, err := yaml.YAMLToJSON(swagger.HiroSwaggerSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to convert spec to json: %w", err)
	}

	perms := make([]PermissionCreateInput, 0)

	for def, sch := range doc.Spec().SecurityDefinitions {
		if sch.Type != "oauth2" {
			continue
		}

		for scope, desc := range sch.Scopes {
			desc := desc
			perms = append(perms, PermissionCreateInput{
				Definition:  def,
				Scope:       scope,
				Description: &desc,
			})
		}
	}

	return h.APICreate(ctx, APICreateParams{
		Name:        info.Title,
		Version:     info.Version,
		Description: &info.Description,
		Spec:        spec,
		Permissions: perms,
	})
}

// ValidateWithContext validates the APICreateInput type
func (p APIGetParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.ID, validation.When(p.Name == nil, validation.Required).Else(validation.Nil)),
		validation.Field(&p.Name, validation.When(p.ID == nil, validation.Required).Else(validation.Nil)),
		validation.Field(&p.Version, validation.When(p.Name != nil, validation.Required).Else(validation.Nil), is.Semver),
	)
}

// APIGet retrieves an api
func (h *Hiro) APIGet(ctx context.Context, params APIGetParams) (*API, error) {
	log := Log(ctx).WithField("operation", "APIGet").WithField("params", params)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

	query := sq.Select("*").
		From("hiro.apis").
		PlaceholderFormat(sq.Dollar)

	if params.ID != nil {
		query = query.Where(sq.Eq{"id": params.ID})
	} else if params.Name != nil {
		query = query.Where(sq.Or{
			sq.Eq{"name": *params.Name},
			sq.Eq{"version": *params.Version},
		})
	}

	stmt, args, err := query.
		ToSql()
	if err != nil {
		log.Error(err.Error())

		return nil, ParseSQLError(err)
	}

	a := &API{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(a); err != nil {
		err = ParseSQLError(err)

		if !errors.Is(err, ErrNotFound) {
			log.Error(err.Error())
		} else {
			log.Debug(err.Error())
		}

		return nil, err
	}

	return h.apiExpand(ctx, a, params.Expand)
}

func (h *Hiro) apiExpand(ctx context.Context, a *API, expand common.StringSlice) (*API, error) {
	db := h.DB(ctx)

	if expand.Contains("permissions") {
		a.Permissions = make([]Permission, 0)

		stmt, args, err := sq.Select("*").
			From("hiro.api_permissions").
			Where(sq.Eq{
				"api_id": a.ID,
			}).
			PlaceholderFormat(sq.Dollar).
			ToSql()
		if err != nil {
			return nil, fmt.Errorf("failed to expand permissions: %w", err)
		}

		if err := db.SelectContext(ctx, &a.Permissions, stmt, args...); err != nil {
			return nil, ParseSQLError(err)
		}
	}

	return a, nil
}
