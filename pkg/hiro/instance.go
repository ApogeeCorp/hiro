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
	"github.com/ModelRocket/hiro/pkg/common"
	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// InstanceController is the instance API interface
	InstanceController interface {
		InstanceCreate(ctx context.Context, params InstanceCreateParams) (*Instance, error)
		InstanceGet(ctx context.Context, params InstanceGetParams) (*Instance, error)
		InstanceList(ctx context.Context, params InstanceListParams) ([]*Instance, error)
		InstanceUpdate(ctx context.Context, params InstanceUpdateParams) (*Instance, error)
		InstanceDelete(ctx context.Context, params InstanceDeleteParams) error
	}

	// Instance is the database model for an instance
	Instance struct {
		ID          ID         `json:"id" db:"id"`
		CreatedAt   time.Time  `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time `json:"updated_at,omitempty" db:"updated_at"`
		DomainID    ID         `json:"domain_id" db:"domain_id"`
		ApiID       ID         `json:"api_id" db:"api_id"`
		Name        string     `json:"name" db:"name"`
		Description *string    `json:"description,omitempty" db:"description"`
		Metadata    common.Map `json:"metadata,omitempty" db:"metadata"`
		API         *API       `json:"api,omitempty" db:"-"`
		Domain      *Domain    `json:"domain,omitempty" db:"-"`
	}

	// InstanceCreateParams is the instance create request
	InstanceCreateParams struct {
		Params
		DomainID    ID      `json:"domain_id"`
		ApiID       ID      `json:"api_id"`
		Name        string  `json:"name"`
		Description *string `json:"description,omitempty"`
	}

	// InstanceUpdateParams is the instance update request
	InstanceUpdateParams struct {
		Params      `structs:"-"`
		DomainID    ID      `json:"domain_id" structs:"-"`
		InstanceID  ID      `json:"instance_id" structs:"-"`
		Name        *string `json:"name" structs:"name,omitempty"`
		Description *string `json:"description,omitempty" structs:"description,omitempty"`
	}

	// InstanceGetParams is used to get an instance for the id
	InstanceGetParams struct {
		Params
		DomainID   *ID     `json:"domain_id,omitempty"`
		InstanceID *ID     `json:"instance_id,omitempty"`
		Name       *string `json:"-"`
		Audience   *string `json:"-"`
	}

	// InstanceListParams is the instance list request
	InstanceListParams struct {
		Params
		DomainID *ID     `json:"domain_id,omitempty"`
		Limit    *uint64 `json:"limit,omitempty"`
		Offset   *uint64 `json:"offset,omitempty"`
		Count    *uint64 `json:"count,omitempty"`
	}

	// InstanceDeleteParams is the instance delete request input
	InstanceDeleteParams struct {
		Params
		InstanceID ID `json:"instance_id"`
	}
)

// ValidateWithContext handles validation of the InstanceCreateInput struct
func (i InstanceCreateParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.Name, validation.Required, validation.Length(3, 256)),
		validation.Field(&i.DomainID, validation.Required),
		validation.Field(&i.ApiID, validation.Required),
	)
}

// ValidateWithContext handles validation of the InstanceUpdateInput struct
func (i InstanceUpdateParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.InstanceID, validation.Required),
		validation.Field(&i.Name, validation.NilOrNotEmpty, validation.Length(3, 64)),
	)
}

// ValidateWithContext handles validation of the InstanceGetInput struct
func (i InstanceGetParams) ValidateWithContext(ctx context.Context) error {
	return nil
}

// ValidateWithContext handles validation of the InstanceListInput struct
func (i InstanceListParams) ValidateWithContext(context.Context) error {
	return nil
}

// ValidateWithContext handles validation of the ApplicationDeleteInput
func (i InstanceDeleteParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.InstanceID, validation.Required),
	)
}

// InstanceCreate create a new permission object
func (h *Hiro) InstanceCreate(ctx context.Context, params InstanceCreateParams) (*Instance, error) {
	var inst Instance

	log := Log(ctx).WithField("operation", "InstanceCreate").WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new instance")

		stmt, args, err := sq.Insert("hiro.instances").
			Columns(
				"domain_id",
				"api_id",
				"name",
				"description",
				"metadata").
			Values(
				params.Name,
				params.DomainID,
				params.ApiID,
				null.String(params.Description),
				null.JSON(params.Metadata),
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(`RETURNING *`).
			ToSql()
		if err != nil {
			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &inst, stmt, args...); err != nil {
			return ParseSQLError(err)
		}

		return nil
	}); err != nil {
		log.Error(err.Error())

		return nil, err
	}

	log.Debugf("instance %s created", inst.ID)

	if !params.Expand.Empty() {
		if err := inst.Expand(h.Context(ctx), params.Expand...); err != nil {
			return nil, err
		}
	}

	return &inst, nil
}

// InstanceUpdate updates an application by id, including child objects
func (h *Hiro) InstanceUpdate(ctx context.Context, params InstanceUpdateParams) (*Instance, error) {
	var inst Instance

	log := Log(ctx).WithField("operation", "InstanceUpdate").WithField("id", params.InstanceID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating instance")

		q := sq.Update("hiro.instances").
			PlaceholderFormat(sq.Dollar)

		updates := structs.Map(params)

		if params.Metadata != nil {
			updates["metadata"] = sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata)
		}

		if len(updates) > 0 {
			stmt, args, err := q.Where(sq.Eq{"id": params.InstanceID}).
				SetMap(updates).
				Suffix("RETURNING *").
				ToSql()
			if err != nil {
				log.Error(err.Error())

				return fmt.Errorf("%w: failed to build query statement", err)
			}

			if err := tx.GetContext(ctx, &inst, stmt, args...); err != nil {
				log.Error(err.Error())

				return ParseSQLError(err)
			}
		} else {
			a, err := h.InstanceGet(ctx, InstanceGetParams{
				InstanceID: &params.InstanceID,
			})
			if err != nil {
				return err
			}
			inst = *a
		}

		return nil
	}); err != nil {
		return nil, err
	}

	log.Debugf("instance %s updated", inst.Name)

	if !params.Expand.Empty() {
		if err := inst.Expand(h.Context(ctx), params.Expand...); err != nil {
			return nil, err
		}
	}

	return &inst, nil
}

// InstanceGet gets an instance by id and optionally preloads child objects
func (h *Hiro) InstanceGet(ctx context.Context, params InstanceGetParams) (*Instance, error) {
	var suffix string

	log := Log(ctx).WithField("operation", "InstanceGet").WithField("params", params)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

	if IsTransaction(db) {
		suffix = "FOR UPDATE"
	}

	query := sq.Select("*").
		From("hiro.instances").
		PlaceholderFormat(sq.Dollar)

	if params.InstanceID != nil {
		query = query.Where(sq.Eq{"id": params.InstanceID})
	} else if params.Name != nil {
		query = query.Where(sq.Or{
			sq.Eq{"name": *params.Name},
		})
	} else if params.Audience != nil {
		query = query.Where(sq.Or{
			sq.Eq{"audience": *params.Audience},
			sq.Expr("? ~ audience", *params.Audience),
		})
	} else {
		return nil, fmt.Errorf("%w: instance id, name, or audience required", ErrInputValidation)
	}

	stmt, args, err := query.
		Suffix(suffix).
		ToSql()
	if err != nil {
		log.Error(err.Error())

		return nil, ParseSQLError(err)
	}

	inst := &Instance{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(inst); err != nil {
		log.Error(err.Error())

		return nil, ParseSQLError(err)
	}

	if !params.Expand.Empty() {
		if err := inst.Expand(h.Context(ctx), params.Expand...); err != nil {
			return nil, err
		}
	}

	return inst, nil
}

// InstanceList returns a listing of instances
func (h *Hiro) InstanceList(ctx context.Context, params InstanceListParams) ([]*Instance, error) {
	log := Log(ctx).WithField("operation", "InstanceList")

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
		From("hiro.instances")

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

	insts := make([]*Instance, 0)
	if err := db.SelectContext(ctx, &insts, stmt, args...); err != nil {
		return nil, ParseSQLError(err)
	}

	if !params.Expand.Empty() {
		for _, inst := range insts {
			if err := inst.Expand(h.Context(ctx), params.Expand...); err != nil {
				return nil, err
			}
		}
	}

	return insts, nil
}

// InstanceDelete deletes an instance by id
func (h *Hiro) InstanceDelete(ctx context.Context, params InstanceDeleteParams) error {
	log := Log(ctx).WithField("operation", "InstanceDelete").WithField("instance", params.InstanceID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)
	if _, err := sq.Delete("hiro.instances").
		Where(
			sq.Eq{"id": params.InstanceID},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to delete instance %s: %s", params.InstanceID, err)
		return ParseSQLError(err)
	}

	return nil
}

func (i *Instance) Expand(ctx context.Context, e ...string) error {
	h := FromContext(ctx)
	if h == nil {
		return ErrContextNotFound
	}

	expand := common.StringSlice(e)

	if expand.ContainsAny("api", "*") {
		a, err := h.APIGet(ctx, APIGetParams{
			Params: Params{
				Expand: expand.FilterPrefix("api"),
			},
			ID: &i.ApiID,
		})
		if err != nil {
			return fmt.Errorf("failed to expand instance api %s: %w", i.ID, err)
		}
		i.API = a
	}

	if expand.ContainsAny("domain", "*") {
		d, err := h.DomainGet(ctx, DomainGetParams{
			Params: Params{
				Expand: expand.FilterPrefix("domain"),
			},
			ID: &i.DomainID,
		})
		if err != nil {
			return fmt.Errorf("failed to expand instance domain %s: %w", i.ID, err)
		}
		i.Domain = d
	}

	return nil
}
