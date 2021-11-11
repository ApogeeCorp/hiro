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
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// DomainController is the Domain management interface
	DomainController interface {
		DomainCreate(ctx context.Context, params DomainCreateParams) (*Domain, error)
		DomainGet(ctx context.Context, params DomainGetParams) (*Domain, error)
	}

	// Domain defines an domain specification managed by hiro
	Domain struct {
		ID          ID           `json:"id" db:"id"`
		CreatedAt   time.Time    `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time   `json:"updated_at,omitempty" db:"updated_at"`
		Name        string       `json:"name" db:"name"`
		Description *string      `json:"description,omitempty" db:"description"`
		Metadata    common.Map   `json:"metadata,omitempty" db:"metadata"`
		Secrets     []Secret     `json:"secrets,omitempty" db:"-"`
		Permissions []Permission `json:"permissions" db:"-"`
		Options     Options      `json:"options,omitempty" db:"-"`
	}

	// DomainCreateParams is the input for DomainCreate
	DomainCreateParams struct {
		Params
		Name        string  `json:"name"`
		Description *string `json:"description,omitempty"`
		Audience    string  `json:"audience"`
	}

	// DomainGetParams is the input for DomainGet
	DomainGetParams struct {
		Params
		ID   *ID     `json:"id,omitempty"`
		Name *string `json:"name,omitempty"`
	}
)

// ValidateWithContext validates the DomainCreateInput type
func (p DomainCreateParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Name, validation.Required, is.DNSName),
		validation.Field(&p.Description, validation.NilOrNotEmpty),
	)
}

// DomainCreate creates a new domain
func (h *Hiro) DomainCreate(ctx context.Context, params DomainCreateParams) (*Domain, error) {
	var dom Domain

	log := Log(ctx).
		WithField("operation", "DomainCreate").
		WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new domain")

		query := sq.Insert("hiro.domains").
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

		if err := tx.GetContext(ctx, &dom, stmt, args...); err != nil {
			return ParseSQLError(err)
		}

		return nil
	}); err != nil {
		log.Error(err.Error())

		return nil, err
	}

	log.Debugf("domain %s created", dom.ID)

	return &dom, nil
}

// ValidateWithContext validates the DomainCreateInput type
func (p DomainGetParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.ID, validation.When(p.Name == nil, validation.Required).Else(validation.Nil)),
		validation.Field(&p.Name, validation.When(p.ID == nil, validation.Required).Else(validation.Nil)),
	)
}

// DomainGet retrieves an domain
func (h *Hiro) DomainGet(ctx context.Context, params DomainGetParams) (*Domain, error) {
	log := Log(ctx).WithField("operation", "DomainGet").WithField("params", params)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

	query := sq.Select("*").
		From("hiro.domains").
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

	d := &Domain{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(d); err != nil {
		err = ParseSQLError(err)

		if !errors.Is(err, ErrNotFound) {
			log.Error(err.Error())
		} else {
			log.Debug(err.Error())
		}

		return nil, err
	}

	if !params.Expand.Empty() {
		if err := d.Expand(h.Context(ctx), params.Expand...); err != nil {
			return nil, err
		}
	}

	return d, nil
}

// Expand implements the expandable interface
func (a *Domain) Expand(ctx context.Context, e ...string) error {
	h := FromContext(ctx)
	if h == nil {
		return ErrContextNotFound
	}

	expand := common.StringSlice(e)

	if expand.ContainsAny("options", "*") {
		ops, err := h.OptionList(ctx, OptionListParams{
			DomainID: a.ID,
		})
		if err != nil {
			return err
		}

		a.Options = ops
	}

	return nil
}
