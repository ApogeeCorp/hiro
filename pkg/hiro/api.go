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
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/ModelRocket/hiro/pkg/common"
	"github.com/go-openapi/loads"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// APIController is the API management interface
	APIController interface {
		APICreate(ctx context.Context, params APICreateParams) (*API, error)
		APIImport(ctx context.Context, params APICreateParams) (*API, error)
		APIGet(ctx context.Context, params APIGetParams) (*API, error)
	}

	// API defines an api specification managed by hiro
	API struct {
		ID          ID           `json:"id" db:"id"`
		CreatedAt   time.Time    `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time   `json:"updated_at,omitempty" db:"updated_at"`
		Name        string       `json:"name" db:"name"`
		Description *string      `json:"description,omitempty" db:"description"`
		Specs       []Spec       `json:"specs,omitempty" db:"-"`
		Permissions []Permission `json:"permissions,omitempty" db:"-"`
		Metadata    common.Map   `json:"metadata,omitempty" db:"metadata"`
	}

	// APICreateParams is the input for APICreate
	APICreateParams struct {
		Params
		Name        string                   `json:"name"`
		Description *string                  `json:"description,omitempty"`
		Specs       []SpecCreateParams       `json:"specs,omitempty"`
		Permissions []PermissionCreateParams `json:"permissions,omitempty"`
	}

	// APIImportParams is the input for APIImport
	APIImportParams struct {
		Params
		*APICreateParams
		SpecCreateParams
	}

	// APIGetParams is the input for APIGet
	APIGetParams struct {
		Params
		ID   *ID     `json:"id,omitempty"`
		Name *string `json:"name,omitempty"`
	}
)

// ValidateWithContext validates the APICreateInput type
func (p APICreateParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Name, validation.Required),
		validation.Field(&p.Description, validation.NilOrNotEmpty),
		validation.Field(&p.Specs, validation.NilOrNotEmpty),
		validation.Field(&p.Permissions, validation.NilOrNotEmpty),
	)
}

// APICreate creates a new api
func (h *Hiro) APICreate(ctx context.Context, params APICreateParams) (*API, error) {
	var api API

	log := Log(ctx).
		WithField("operation", "APICreate").
		WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new api")

		query := sq.Insert("hiro.apis").
			Columns(
				"name",
				"description",
			).
			Values(
				params.Name,
				params.Description,
			).
			PlaceholderFormat(sq.Dollar)

		if params.UpdateOnConflict {
			query = query.Suffix(
				`ON CONFLICT (name) DO UPDATE SET description=$3 RETURNING *`,
				params.Description,
			)
		} else {
			query = query.Suffix("RETURNING *")
		}

		stmt, args, err := query.ToSql()
		if err != nil {
			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &api, stmt, args...); err != nil {
			return ParseSQLError(err)
		}

		// create any necessary permissions
		for _, p := range params.Permissions {
			p.ApiID = api.ID
			p.Params = params.Params

			if _, err := h.PermissionCreate(ctx, p); err != nil {
				return err
			}
		}

		// create any necessary specs
		for _, s := range params.Specs {
			s.ApiID = api.ID
			s.Params = params.Params

			if _, err := h.SpecCreate(ctx, s); err != nil {
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
		validation.Field(&p.APICreateParams, validation.NilOrNotEmpty),
		validation.Field(&p.SpecCreateParams, validation.Required),
	)
}

// APIImport imports an api definition
func (h *Hiro) APIImport(ctx context.Context, params APIImportParams) (*API, error) {
	log := Log(ctx).
		WithField("operation", "APIImport")

	switch params.SpecType {
	case SpecTypeOpenAPI:
		switch params.SpecFormat {
		case SpecFormatSwagger:
			// intialize the hiro api
			doc, err := loads.Analyzed(params.Spec, "")
			if err != nil {
				return nil, fmt.Errorf("failed to load swagger document: %w", err)
			}
			info := doc.Spec().Info

			if params.APICreateParams == nil {
				params.APICreateParams = &APICreateParams{
					Name:        info.Title,
					Description: &info.Description,
				}
			}
		}
	}

	log.Debugf("importing api %s", params.Name)

	return h.APICreate(ctx, APICreateParams{
		Params: Params{
			UpdateOnConflict: params.UpdateOnConflict,
		},
		Name:        params.Name,
		Description: params.Description,
		Specs: []SpecCreateParams{
			params.SpecCreateParams,
		},
	})
}

// ValidateWithContext validates the APICreateInput type
func (p APIGetParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.ID, validation.When(p.Name == nil, validation.Required).Else(validation.Nil)),
		validation.Field(&p.Name, validation.When(p.ID == nil, validation.Required).Else(validation.Nil)),
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

	if !params.Expand.Empty() {
		if err := a.Expand(h.Context(ctx), params.Expand...); err != nil {
			return nil, err
		}
	}

	return a, nil
}

// Expand implements the expandable interface
func (a *API) Expand(ctx context.Context, e ...string) error {
	h := FromContext(ctx)
	if h == nil {
		return ErrContextNotFound
	}

	db := h.DB(ctx)

	expand := common.StringSlice(e)

	if expand.ContainsAny("permissions", "*") {
		a.Permissions = make([]Permission, 0)

		stmt, args, err := sq.Select("*").
			From("hiro.api_permissions").
			Where(sq.Eq{
				"api_id": a.ID,
			}).
			PlaceholderFormat(sq.Dollar).
			ToSql()
		if err != nil {
			return fmt.Errorf("failed to expand permissions: %w", err)
		}

		if err := db.SelectContext(ctx, &a.Permissions, stmt, args...); err != nil {
			return ParseSQLError(err)
		}
	}

	if expand.ContainsAnyPrefix("specs", "*") {
		a.Specs = make([]Spec, 0)

		stmt, args, err := sq.Select("*").
			From("hiro.api_specs").
			Where(sq.Eq{
				"api_id": a.ID,
			}).
			PlaceholderFormat(sq.Dollar).
			ToSql()
		if err != nil {
			return fmt.Errorf("failed to expand permissions: %w", err)
		}

		if err := db.SelectContext(ctx, &a.Permissions, stmt, args...); err != nil {
			return ParseSQLError(err)
		}

		for _, s := range a.Specs {
			if err := (&s).Expand(ctx, expand.FilterPrefix("specs")...); err != nil {
				return err
			}
		}
	}

	return nil
}
