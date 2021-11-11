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
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/ModelRocket/hiro/pkg/oauth"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// PermissionController is the permission API interface
	PermissionController interface {
		PermissionCreate(ctx context.Context, params PermissionCreateParams) (*Permission, error)
	}

	// Permission is an api permission object
	Permission struct {
		ID          ID         `json:"id" db:"id"`
		CreatedAt   time.Time  `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time `json:"updated_at,omitempty" db:"updated_at"`
		ApiID       ID         `json:"api_id" db:"api_id"`
		SpecID      *ID        `json:"spec_id,omitempty" db:"spec_id"`
		Definition  string     `jsoon:"definition" db:"definition"`
		Scope       string     `json:"scope" db:"scope"`
		Description *string    `json:"description,omitempty" db:"description"`
	}

	PermissionCreateParams struct {
		Params
		ApiID       ID      `json:"api_id"`
		SpecID      *ID     `json:"spec_id,omitempty"`
		Definition  string  `jsoon:"definition"`
		Scope       string  `json:"scope"`
		Description *string `json:"description,omitempty"`
	}
)

// ValidateWithContext validates the PermissionCreateInput type
func (i PermissionCreateParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.ApiID, validation.Required),
		validation.Field(&i.Definition, validation.Required),
		validation.Field(&i.Scope, validation.Required, oauth.IsValidScope),
		validation.Field(&i.Description, validation.NilOrNotEmpty),
	)
}

func (h *Hiro) PermissionCreate(ctx context.Context, params PermissionCreateParams) (*Permission, error) {
	var perm Permission

	log := Log(ctx).WithField("operation", "PermissionCreate").WithField("params", params)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new permission")

		query := sq.Insert("hiro.api_permissions").
			Columns(
				"api_id",
				"spec_id",
				"definition",
				"scope",
				"description",
			).
			Values(
				params.ApiID,
				params.SpecID,
				params.Definition,
				params.Scope,
				params.Description,
			).
			PlaceholderFormat(sq.Dollar)

		if params.UpdateOnConflict {
			query = query.Suffix(`ON CONFLICT ON CONSTRAINT api_permission_scope DO UPDATE SET description=$6 RETURNING *`, params.Description)
		} else {
			query = query.Suffix("RETURNING *")
		}

		stmt, args, err := query.ToSql()
		if err != nil {
			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &perm, stmt, args...); err != nil {
			return ParseSQLError(err)
		}

		return nil
	}); err != nil {
		log.Error(err.Error())

		return nil, err
	}

	log.Debugf("permission %s created", perm.ID)

	return &perm, nil
}
