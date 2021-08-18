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
	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// RoleController is roles API interfcace
	RoleController interface {
		RoleCreate(ctx context.Context, params RoleCreateInput) (*Role, error)
		RoleGet(ctx context.Context, params RoleGetInput) (*Role, error)
		RoleList(ctx context.Context, params RoleListInput) ([]*Role, error)
		RoleUpdate(ctx context.Context, params RoleUpdateInput) (*Role, error)
		RoleDelete(ctx context.Context, params RoleDeleteInput) error
	}

	// Role is the database model for an role
	Role struct {
		ID          ID           `json:"id" db:"id"`
		InstanceID  ID           `json:"instance_id" db:"instance_id"`
		Name        string       `json:"name" db:"name"`
		Description *string      `json:"description,omitempty" db:"description"`
		Default     bool         `json:"default" db:"is_default"`
		Permissions []Permission `json:"permissions,omitempty" db:"-"`
		CreatedAt   time.Time    `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time   `json:"updated_at,omitempty" db:"updated_at"`
		Metadata    common.Map   `json:"metadata,omitempty" db:"metadata"`
	}

	// RoleCreateInput is the role create request
	RoleCreateInput struct {
		InstanceID  ID           `json:"instance_id"`
		Name        string       `json:"name"`
		Description *string      `json:"description,omitempty"`
		Default     bool         `json:"default"`
		Permissions []Permission `json:"permissions,omitempty"`
		Metadata    common.Map   `json:"metadata,omitempty"`
	}

	// RoleUpdateInput is the role update request
	RoleUpdateInput struct {
		InstanceID  ID               `json:"-"`
		RoleID      ID               `json:"id" structs:"-"`
		Name        *string          `json:"name" structs:"name,omitempty"`
		Description *string          `json:"description,omitempty" structs:"description,omitempty"`
		Default     *bool            `json:"default,omitempty" structs:"default,omitempty"`
		Permissions PermissionUpdate `json:"permissions,omitempty" structs:"-"`
		Metadata    common.Map       `json:"metadata,omitempty" structs:"metadata,omitempty"`
	}

	// RoleGetInput is used to get an role for the id
	RoleGetInput struct {
		RoleID     *ID                `json:"role_id,omitempty"`
		InstanceID ID                 `json:"-"`
		Expand     common.StringSlice `json:"expand,omitempty"`
		Name       *string            `json:"-"`
	}

	// RoleListInput is the role list request
	RoleListInput struct {
		InstanceID ID                 `json:"-"`
		Expand     common.StringSlice `json:"expand,omitempty"`
		Limit      *uint64            `json:"limit,omitempty"`
		Offset     *uint64            `json:"offset,omitempty"`
	}

	// RoleDeleteInput is the role delete request input
	RoleDeleteInput struct {
		InstanceID ID `json:"-"`
		RoleID     ID `json:"role_id"`
	}

	// RoleType defines an role type
	RoleType string

	rolePatchInput struct {
		Role        *Role
		Permissions PermissionUpdate
	}
)

// ValidateWithContext handles validation of the RoleCreateInput struct
func (a RoleCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.Name, validation.Required, validation.Length(3, 64)),
		validation.Field(&a.Description, validation.NilOrNotEmpty),
		validation.Field(&a.Permissions, validation.Required),
	)
}

// ValidateWithContext handles validation of the RoleUpdateInput struct
func (a RoleUpdateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.RoleID, validation.Required),
		validation.Field(&a.Name, validation.NilOrNotEmpty, validation.Length(3, 64)),
		validation.Field(&a.Description, validation.NilOrNotEmpty),
		validation.Field(&a.Permissions, validation.NilOrNotEmpty),
	)
}

// ValidateWithContext handles validation of the RoleGetInput struct
func (a RoleGetInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.RoleID, validation.When(a.Name == nil, validation.Required).Else(validation.Nil)),
		validation.Field(&a.Name, validation.When(a.RoleID == nil, validation.Required).Else(validation.Nil)),
	)
}

// ValidateWithContext handles validation of the RoleListInput struct
func (a RoleListInput) ValidateWithContext(context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.InstanceID, validation.Required),
	)
}

// ValidateWithContext handles validation of the RoleDeleteInput
func (a RoleDeleteInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.RoleID, validation.Required),
	)
}

// RoleCreate create a new permission object
func (h *Hiro) RoleCreate(ctx context.Context, params RoleCreateInput) (*Role, error) {
	var role Role

	log := Log(ctx).WithField("operation", "RoleCreate").WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new role")

		stmt, args, err := sq.Insert("hiro.roles").
			Columns(
				"instance_id",
				"name",
				"description",
				"default",
				"metadata").
			Values(
				params.InstanceID,
				params.Name,
				null.String(params.Description),
				params.Default,
				null.JSON(params.Metadata),
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(`RETURNING *`).
			ToSql()
		if err != nil {
			log.Error(err.Error())

			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &role, stmt, args...); err != nil {
			return ParseSQLError(err)
		}

		return h.rolePatch(ctx, rolePatchInput{
			Role: &role,
			Permissions: PermissionUpdate{
				Add: params.Permissions,
			},
		})
	}); err != nil {
		if errors.Is(err, ErrDuplicateObject) {
			r, err := h.RoleGet(ctx, RoleGetInput{
				Name: &params.Name,
			})
			if err != nil {
				return nil, err
			}

			role = *r
		} else {
			log.Error(err.Error())
		}

		return &role, err
	}

	log.Debugf("role %s created", role.ID)

	return h.roleExpand(ctx, &role, expandAll)
}

// RoleUpdate updates an role by id, including child objects
func (h *Hiro) RoleUpdate(ctx context.Context, params RoleUpdateInput) (*Role, error) {
	var role Role

	log := Log(ctx).WithField("operation", "RoleUpdate").WithField("id", params.RoleID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating role")

		q := sq.Update("hiro.roles").
			PlaceholderFormat(sq.Dollar)

		updates := structs.Map(params)

		if params.Metadata != nil {
			updates["metadata"] = sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata)
		}

		if len(updates) > 0 {
			stmt, args, err := q.Where(sq.Eq{
				"instance_id": params.InstanceID,
				"id":          params.RoleID,
			}).
				SetMap(updates).
				Suffix("RETURNING *").
				ToSql()
			if err != nil {
				log.Error(err.Error())

				return fmt.Errorf("%w: failed to build query statement", err)
			}

			if err := tx.GetContext(ctx, &role, stmt, args...); err != nil {
				log.Error(err.Error())

				return ParseSQLError(err)
			}
		} else {
			a, err := h.RoleGet(ctx, RoleGetInput{
				RoleID: &params.RoleID,
			})
			if err != nil {
				return err
			}
			role = *a
		}

		return h.rolePatch(ctx, rolePatchInput{
			Role:        &role,
			Permissions: params.Permissions,
		})
	}); err != nil {
		return nil, err
	}

	log.Debugf("role %s updated", role.Name)

	return h.roleExpand(ctx, &role, expandAll)
}

// RoleGet gets an role by id and optionally preloads child objects
func (h *Hiro) RoleGet(ctx context.Context, params RoleGetInput) (*Role, error) {
	var suffix string

	log := Log(ctx).WithField("operation", "RoleGet").
		WithField("id", params.RoleID).
		WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

	query := sq.Select("*").
		From("hiro.roles").
		PlaceholderFormat(sq.Dollar).
		Where(sq.Eq{"instance_id": params.InstanceID})

	if params.RoleID != nil {
		query = query.Where(sq.Eq{"id": *params.RoleID})
	} else if params.Name != nil {
		query = query.Where(sq.Or{
			sq.Eq{"name": *params.Name},
			sq.Eq{"slug": *params.Name},
		})
	} else {
		return nil, fmt.Errorf("%w: role id or name required", ErrInputValidation)
	}

	stmt, args, err := query.
		Suffix(suffix).
		ToSql()
	if err != nil {
		log.Error(err.Error())

		return nil, ParseSQLError(err)
	}

	role := Role{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(&role); err != nil {
		log.Error(err.Error())

		return nil, ParseSQLError(err)
	}

	return h.roleExpand(ctx, &role, params.Expand)
}

// RoleList returns a listing of roles
func (h *Hiro) RoleList(ctx context.Context, params RoleListInput) ([]*Role, error) {
	log := Log(ctx).WithField("operation", "RoleList")

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

	query := sq.Select("*").
		From("hiro.roles").
		Where(sq.Eq{"instance_id": params.InstanceID})

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

	roles := make([]*Role, 0)
	if err := db.SelectContext(ctx, &roles, stmt, args...); err != nil {
		return nil, ParseSQLError(err)
	}

	for _, role := range roles {
		if _, err = h.roleExpand(ctx, role, params.Expand); err != nil {
			return nil, err
		}
	}

	return roles, nil
}

func (h *Hiro) rolePatch(ctx context.Context, params rolePatchInput) error {
	log := Log(ctx).WithField("operation", "rolePatch").WithField("role", params.Role.ID)

	db := h.DB(ctx)

	for _, p := range params.Permissions.Add {
		_, err := sq.Insert("hiro.role_permissions").
			Columns("role_id", "instance_id", "permission").
			Values(
				params.Role.ID,
				params.Role.InstanceID,
				p.Scope,
			).
			Suffix("ON CONFLICT DO NOTHING").
			RunWith(db).
			PlaceholderFormat(sq.Dollar).
			ExecContext(ctx)
		if err != nil {
			log.Errorf("failed to update instance permissions %s: %s", params.Role.InstanceID, err)

			return ParseSQLError(err)
		}
	}

	for _, p := range params.Permissions.Remove {
		if _, err := sq.Delete("hiro.role_permissions").
			Where(
				sq.Eq{
					"instance_id": params.Role.InstanceID,
					"role_id":     params.Role.ID,
					"permission":  p.Scope,
				}).
			PlaceholderFormat(sq.Dollar).
			RunWith(db).
			ExecContext(ctx); err != nil {
			log.Errorf("failed to delete roles for instance %s: %s", params.Role.InstanceID, err)

			return ParseSQLError(err)
		}

	}

	return nil
}

// RoleDelete deletes an role by id
func (h *Hiro) RoleDelete(ctx context.Context, params RoleDeleteInput) error {
	log := Log(ctx).WithField("operation", "RoleDelete").WithField("role", params.RoleID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)
	if _, err := sq.Delete("hiro.roles").
		Where(
			sq.Eq{"id": params.RoleID},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to delete role %s: %s", params.RoleID, err)
		return ParseSQLError(err)
	}

	return nil
}

func (h *Hiro) roleExpand(ctx context.Context, role *Role, expand common.StringSlice) (*Role, error) {
	log := Log(ctx).WithField("operation", "roleExpand").WithField("role", role.ID)

	db := h.DB(ctx)

	if expand.ContainsAny("permissions", "*") {
		if err := db.SelectContext(
			ctx,
			&role.Permissions,
			`SELECT instance_id, permission 
		  FROM hiro.role_permissions
		  WHERE role_id=$1`,
			role.ID); err != nil {
			log.Errorf("failed to load role permissions %s: %s", role.ID, err)

			return nil, ParseSQLError(err)
		}
	}

	return role, nil
}
