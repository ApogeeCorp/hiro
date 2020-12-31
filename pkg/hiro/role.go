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
	"github.com/ModelRocket/sparks/pkg/oauth"
	"github.com/ModelRocket/reno/pkg/null"
	"github.com/ModelRocket/reno/pkg/reno"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// Role is the database model for an role
	Role struct {
		ID          ID                `json:"id" db:"id"`
		Name        string            `json:"name" db:"name"`
		Slug        string            `json:"slug" db:"slug"`
		Description *string           `json:"description,omitempty" db:"description"`
		Permissions oauth.ScopeSet    `json:"permissions,omitempty" db:"-"`
		CreatedAt   time.Time         `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time        `json:"updated_at,omitempty" db:"updated_at"`
		Metadata    reno.InterfaceMap `json:"metadata,omitempty" db:"metadata"`
	}

	// RoleCreateInput is the role create request
	RoleCreateInput struct {
		Name        string            `json:"name"`
		Description *string           `json:"description,omitempty"`
		Permissions oauth.ScopeSet    `json:"permissions,omitempty"`
		Metadata    reno.InterfaceMap `json:"metadata,omitempty"`
	}

	// RoleUpdateInput is the role update request
	RoleUpdateInput struct {
		RoleID      ID                 `json:"id" structs:"-"`
		Name        *string            `json:"name" structs:"name,omitempty"`
		Description *string            `json:"description,omitempty" structs:"description,omitempty"`
		Permissions *PermissionsUpdate `json:"permissions,omitempty" structs:"-"`
		Metadata    reno.InterfaceMap  `json:"metadata,omitempty" structs:"metadata,omitempty"`
	}

	// RoleGetInput is used to get an role for the id
	RoleGetInput struct {
		RoleID  *ID     `json:"role_id,omitempty"`
		Name    *string `json:"name,omitempty"`
		Preload *bool   `json:"preload,omitempty"`
	}

	// RoleListInput is the role list request
	RoleListInput struct {
		Limit  *uint64 `json:"limit,omitempty"`
		Offset *uint64 `json:"offset,omitempty"`
	}

	// RoleDeleteInput is the role delete request input
	RoleDeleteInput struct {
		RoleID ID `json:"role_id"`
	}

	// RoleType defines an role type
	RoleType string

	rolePatchInput struct {
		Role        *Role
		Permissions *PermissionsUpdate
	}
)

// ValidateWithContext handles validation of the RoleCreateInput struct
func (a RoleCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.Name, validation.Required, validation.Length(3, 64)),
		validation.Field(&a.Description, validation.NilOrNotEmpty),
		validation.Field(&a.Permissions, validation.NilOrNotEmpty),
	)
}

// ValidateWithContext handles validation of the RoleUpdateInput struct
func (a RoleUpdateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.RoleID, validation.Required),
		validation.Field(&a.Name, validation.NilOrNotEmpty, validation.Length(3, 64)),
		validation.Field(&a.Description, validation.NilOrNotEmpty),
		validation.Field(&a.Permissions, validation.NilOrNotEmpty),
	)
}

// ValidateWithContext handles validation of the RoleGetInput struct
func (a RoleGetInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.RoleID, validation.When(a.Name == nil, validation.Required).Else(validation.Nil)),
		validation.Field(&a.Name, validation.When(a.RoleID == nil, validation.Required).Else(validation.Nil)),
	)
}

// ValidateWithContext handles validation of the RoleListInput struct
func (a RoleListInput) ValidateWithContext(context.Context) error {
	return nil
}

// ValidateWithContext handles validation of the RoleDeleteInput
func (a RoleDeleteInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.RoleID, validation.Required),
	)
}

// RoleCreate create a new permission object
func (b *Backend) RoleCreate(ctx context.Context, params RoleCreateInput) (*Role, error) {
	var role Role

	log := b.Log(ctx).WithField("operation", "RoleCreate").WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new role")

		stmt, args, err := sq.Insert("hiro.roles").
			Columns(
				"name",
				"description",
				"metadata").
			Values(
				params.Name,
				null.String(params.Description),
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

		return b.rolePatch(ctx, rolePatchInput{&role, &PermissionsUpdate{Add: params.Permissions}})
	}); err != nil {
		if errors.Is(err, ErrDuplicateObject) {
			r, err := b.RoleGet(ctx, RoleGetInput{
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

	return b.rolePreload(ctx, &role)
}

// RoleUpdate updates an role by id, including child objects
func (b *Backend) RoleUpdate(ctx context.Context, params RoleUpdateInput) (*Role, error) {
	var role Role

	log := b.Log(ctx).WithField("operation", "RoleUpdate").WithField("id", params.RoleID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating role")

		q := sq.Update("hiro.roles").
			PlaceholderFormat(sq.Dollar)

		updates := structs.Map(params)

		if params.Metadata != nil {
			updates["metadata"] = sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata)
		}

		if len(updates) > 0 {
			stmt, args, err := q.Where(sq.Eq{"id": params.RoleID}).
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
			a, err := b.RoleGet(ctx, RoleGetInput{
				RoleID: &params.RoleID,
			})
			if err != nil {
				return err
			}
			role = *a
		}

		return b.rolePatch(ctx, rolePatchInput{&role, params.Permissions})
	}); err != nil {
		return nil, err
	}

	log.Debugf("role %s updated", role.Name)

	return b.rolePreload(ctx, &role)
}

// RoleGet gets an role by id and optionally preloads child objects
func (b *Backend) RoleGet(ctx context.Context, params RoleGetInput) (*Role, error) {
	var suffix string

	log := b.Log(ctx).WithField("operation", "RoleGet").
		WithField("id", params.RoleID).
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
		From("hiro.roles").
		PlaceholderFormat(sq.Dollar)

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

	if params.Preload != nil && !*params.Preload {
		return &role, nil
	}

	return b.rolePreload(ctx, &role)
}

// RoleList returns a listing of roles
func (b *Backend) RoleList(ctx context.Context, params RoleListInput) ([]*Role, error) {
	log := b.Log(ctx).WithField("operation", "RoleList")

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)

	query := sq.Select("*").
		From("hiro.roles")

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
		if _, err = b.rolePreload(ctx, role); err != nil {
			return nil, err
		}
	}

	return roles, nil
}

func (b *Backend) rolePatch(ctx context.Context, params rolePatchInput) error {
	log := b.Log(ctx).WithField("operation", "rolePatch").WithField("role", params.Role.ID)

	db := b.DB(ctx)

	for audID, perms := range params.Permissions.Add {
		if !ID(audID).Valid() {
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

		if params.Permissions.Overwrite {
			if _, err := sq.Delete("hiro.role_permissions").
				Where(
					sq.Eq{
						"audience_id": ID(audID),
						"role_id":     params.Role.ID,
					}).
				PlaceholderFormat(sq.Dollar).
				RunWith(db).
				ExecContext(ctx); err != nil {
				log.Errorf("failed to delete permissions for audience: %s", audID, err)

				return ParseSQLError(err)
			}
		}

		for _, p := range perms.Unique() {
			_, err := sq.Insert("hiro.role_permissions").
				Columns("role_id", "audience_id", "permission").
				Values(
					params.Role.ID,
					ID(audID),
					p,
				).
				Suffix("ON CONFLICT DO NOTHING").
				RunWith(db).
				PlaceholderFormat(sq.Dollar).
				ExecContext(ctx)
			if err != nil {
				log.Errorf("failed to update audience permissions %s: %s", audID, err)

				return ParseSQLError(err)
			}
		}
	}

	for audID, perms := range params.Permissions.Remove {
		if !ID(audID).Valid() {
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

		for _, p := range perms {
			if _, err := sq.Delete("hiro.role_permissions").
				Where(
					sq.Eq{
						"audience_id": ID(audID),
						"role_id":     params.Role.ID,
						"permission":  p,
					}).
				PlaceholderFormat(sq.Dollar).
				RunWith(db).
				ExecContext(ctx); err != nil {
				log.Errorf("failed to delete permissions for audience: %s", audID, err)

				return ParseSQLError(err)
			}
		}
	}

	return nil
}

func (b *Backend) rolePreload(ctx context.Context, role *Role) (*Role, error) {
	log := b.Log(ctx).WithField("operation", "rolePreload").WithField("role", role.ID)

	db := b.DB(ctx)

	perms := []struct {
		Audience   string `db:"audience"`
		Permission string `db:"permission"`
	}{}

	if err := db.SelectContext(
		ctx,
		&perms,
		`SELECT a.name as audience, p.permission 
		  FROM hiro.role_permissions p
		  LEFT JOIN hiro.audiences a
			  ON  a.id = p.audience_id
		  WHERE p.role_id=$1`,
		role.ID); err != nil {
		log.Errorf("failed to load role permissions %s: %s", role.ID, err)

		return nil, ParseSQLError(err)
	}

	role.Permissions = make(oauth.ScopeSet)
	for _, p := range perms {
		role.Permissions.Append(p.Audience, p.Permission)
	}

	return role, nil
}

// RoleDelete deletes an role by id
func (b *Backend) RoleDelete(ctx context.Context, params RoleDeleteInput) error {
	log := b.Log(ctx).WithField("operation", "RoleDelete").WithField("role", params.RoleID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)
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
