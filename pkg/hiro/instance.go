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
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// InstanceController is the instance API interface
	InstanceController interface {
		InstanceCreate(ctx context.Context, params InstanceCreateInput) (*Instance, error)
		InstanceGet(ctx context.Context, params InstanceGetInput) (*Instance, error)
		InstanceList(ctx context.Context, params InstanceListInput) ([]*Instance, error)
		InstanceUpdate(ctx context.Context, params InstanceUpdateInput) (*Instance, error)
		InstanceDelete(ctx context.Context, params InstanceDeleteInput) error
	}

	// Instance is the database model for an instance
	Instance struct {
		ID                   ID                   `json:"id" db:"id"`
		Name                 string               `json:"name" db:"name"`
		Slug                 string               `json:"slug" db:"slug"`
		Audience             string               `json:"audience" db:"audience"`
		Description          *string              `json:"description,omitempty" db:"description"`
		TokenSecrets         []oauth.TokenSecret  `json:"-" db:"-"`
		SessionKeys          []SessionKey         `json:"-" db:"-"`
		Secrets              []Secret             `json:"secrets,omitempty" db:"-"`
		TokenAlgorithm       oauth.TokenAlgorithm `json:"token_algorithm" db:"token_algorithm"`
		TokenLifetime        time.Duration        `json:"token_lifetime" db:"token_lifetime"`
		SessionLifetime      time.Duration        `json:"session_lifetime" db:"session_lifetime"`
		RefreshTokenLifetime time.Duration        `json:"refresh_token_lifetime" db:"refresh_token_lifetime"`
		LoginTokenLifetime   time.Duration        `json:"login_token_lifetime" db:"login_token_lifetime"`
		InviteTokenLifetime  time.Duration        `json:"invite_token_lifetime" db:"invite_token_lifetime"`
		VerifyTokenLifetime  time.Duration        `json:"verify_token_lifetime" db:"verify_token_lifetime"`
		AuthCodeLifetime     time.Duration        `json:"auth_code_lifetime" db:"auth_code_lifetime"`
		CreatedAt            time.Time            `json:"created_at" db:"created_at"`
		UpdatedAt            *time.Time           `json:"updated_at,omitempty" db:"updated_at"`
		Roles                []Role               `json:"roles,omitempty" db:"-"`
		Permissions          []Permission         `json:"permissions,omitempty,omitempty" db:"-"`
		Metadata             common.Map           `json:"metadata,omitempty" db:"metadata"`
	}

	// Permission is an application permission entry
	Permission struct {
		InstanceID  ID     `json:"instance_id"`
		Permission  string `json:"permission"`
		Description string `json:"description,omitempty"`
	}

	// InstanceCreateInput is the instance create request
	InstanceCreateInput struct {
		Name                 string               `json:"name"`
		Description          *string              `json:"description,omitempty"`
		Audience             *string              `json:"audience,omitempty" db:"audience"`
		TokenLifetime        *time.Duration       `json:"token_lifetime,omitempty"`
		TokenAlgorithm       oauth.TokenAlgorithm `json:"token_algorithm"`
		SessionLifetime      *time.Duration       `json:"session_lifetime,omitempty"`
		RefreshTokenLifetime *time.Duration       `json:"refresh_token_lifetime,omitempty"`
		LoginTokenLifetime   *time.Duration       `json:"login_token_lifetime,omitempty"`
		InviteTokenLifetime  *time.Duration       `json:"invite_token_lifetime,omitempty"`
		VerifyTokenLifetime  *time.Duration       `json:"verify_token_lifetime,omitempty"`
		AuthCodeLifetime     *time.Duration       `json:"auth_code_lifetime,omitempty"`
		Permissions          []Permission         `json:"permissions,omitempty"`
		Metadata             common.Map           `json:"metadata,omitempty"`
	}

	// InstanceUpdateInput is the instance update request
	InstanceUpdateInput struct {
		InstanceID           ID                    `json:"instance_id" structs:"-"`
		Name                 *string               `json:"name" structs:"name,omitempty"`
		Description          *string               `json:"description,omitempty" structs:"description,omitempty"`
		Audience             string                `json:"audience" structs:"audience"`
		TokenAlgorithm       *oauth.TokenAlgorithm `json:"token_algorithm,omitempty" structs:"token_algorithm,omitempty"`
		TokenLifetime        *time.Duration        `json:"token_lifetime" structs:"token_lifetime,omitempty"`
		SessionLifetime      *time.Duration        `json:"session_lifetime,omitempty" structs:"session_lifetime,omitempty"`
		RefreshTokenLifetime *time.Duration        `json:"refresh_token_lifetime,omitempty" structs:"refresh_token_lifetime,omitempty"`
		LoginTokenLifetime   *time.Duration        `json:"login_token_lifetime,omitempty" structs:"login_token_lifetime,omitempty"`
		InviteTokenLifetime  *time.Duration        `json:"invite_token_lifetime,omitempty" structs:"invite_token_lifetime,omitempty"`
		VerifyTokenLifetime  *time.Duration        `json:"verify_token_lifetime,omitempty" structs:"verify_token_lifetime,omitempty"`
		AuthCodeLifetime     *time.Duration        `json:"auth_code_lifetime,omitempty" structs:"auth_code_lifetime,omitempty"`
		Permissions          PermissionUpdate      `json:"permissions,omitempty" structs:"-"`
		Metadata             common.Map            `json:"metadata,omitempty" structs:"-"`
	}

	// InstanceGetInput is used to get an instance for the id
	InstanceGetInput struct {
		InstanceID *ID                `json:"instance_id,omitempty"`
		Name       *string            `json:"-"`
		Audience   *string            `json:"-"`
		Expand     common.StringSlice `json:"expand,omitempty"`
	}

	// InstanceListInput is the instance list request
	InstanceListInput struct {
		Limit  *uint64            `json:"limit,omitempty"`
		Offset *uint64            `json:"offset,omitempty"`
		Count  *uint64            `json:"count,omitempty"`
		Expand common.StringSlice `json:"expand,omitempty"`
	}

	// InstanceDeleteInput is the instance delete request input
	InstanceDeleteInput struct {
		InstanceID ID `json:"instance_id"`
	}
)

// ValidateWithContext handles validation of the InstanceCreateInput struct
func (a InstanceCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.Name, validation.Required, validation.Length(3, 64)),
		validation.Field(&a.Audience, validation.Required, is.Domain),
		validation.Field(&a.Permissions, validation.Required),
		validation.Field(&a.TokenAlgorithm, validation.Required),
		validation.Field(&a.TokenLifetime, validation.NilOrNotEmpty, validation.Min(time.Hour)),
		validation.Field(&a.SessionLifetime, validation.NilOrNotEmpty, validation.Min(time.Hour)),
		validation.Field(&a.RefreshTokenLifetime, validation.NilOrNotEmpty, validation.Min(time.Hour)),
		validation.Field(&a.LoginTokenLifetime, validation.NilOrNotEmpty, validation.Min(time.Minute)),
		validation.Field(&a.InviteTokenLifetime, validation.NilOrNotEmpty, validation.Min(time.Minute)),
		validation.Field(&a.VerifyTokenLifetime, validation.NilOrNotEmpty, validation.Min(time.Minute)),
		validation.Field(&a.AuthCodeLifetime, validation.NilOrNotEmpty, validation.Min(time.Minute)),
	)
}

// ValidateWithContext handles validation of the InstanceUpdateInput struct
func (a InstanceUpdateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.Name, validation.NilOrNotEmpty, validation.Length(3, 64)),
		validation.Field(&a.Audience, validation.NilOrNotEmpty, is.Domain),
		validation.Field(&a.TokenAlgorithm, validation.NilOrNotEmpty),
		validation.Field(&a.Permissions, validation.NilOrNotEmpty),
		validation.Field(&a.TokenLifetime, validation.NilOrNotEmpty, validation.Min(time.Hour)),
		validation.Field(&a.SessionLifetime, validation.Required, validation.Min(time.Hour)),
		validation.Field(&a.RefreshTokenLifetime, validation.Required, validation.Min(time.Hour)),
	)
}

// ValidateWithContext handles validation of the InstanceGetInput struct
func (a InstanceGetInput) ValidateWithContext(ctx context.Context) error {
	return nil
}

// ValidateWithContext handles validation of the InstanceListInput struct
func (a InstanceListInput) ValidateWithContext(context.Context) error {
	return nil
}

// ValidateWithContext handles validation of the ApplicationDeleteInput
func (a InstanceDeleteInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.InstanceID, validation.Required),
	)
}

// InstanceCreate create a new permission object
func (h *Hiro) InstanceCreate(ctx context.Context, params InstanceCreateInput) (*Instance, error) {
	var inst Instance

	log := Log(ctx).WithField("operation", "InstanceCreate").WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if params.TokenLifetime == nil {
		params.TokenLifetime = ptr.Duration(time.Hour)
	}

	if params.SessionLifetime == nil {
		params.SessionLifetime = ptr.Duration(time.Hour * 24 * 7)
	}

	if params.RefreshTokenLifetime == nil {
		params.RefreshTokenLifetime = ptr.Duration(time.Hour * 24 * 7)
	}

	if params.LoginTokenLifetime == nil {
		params.LoginTokenLifetime = ptr.Duration(time.Minute * 15)
	}

	if params.InviteTokenLifetime == nil {
		params.InviteTokenLifetime = ptr.Duration(time.Hour * 24 * 7)
	}

	if params.VerifyTokenLifetime == nil {
		params.VerifyTokenLifetime = ptr.Duration(time.Hour * 24)
	}

	if params.AuthCodeLifetime == nil {
		params.AuthCodeLifetime = ptr.Duration(time.Minute * 10)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new instance")

		stmt, args, err := sq.Insert("hiro.instances").
			Columns(
				"name",
				"description",
				"audience",
				"token_algorithm",
				"token_lifetime",
				"session_lifetime",
				"refresh_token_lifetime",
				"login_token_lifetime",
				"invite_token_lifetime",
				"verify_token_lifetime",
				"auth_code_lifetime",
				"metadata").
			Values(
				params.Name,
				null.String(params.Description),
				null.String(params.Audience),
				params.TokenAlgorithm,
				int64(params.TokenLifetime.Round(time.Second).Seconds()),
				int64(params.SessionLifetime.Round(time.Second).Seconds()),
				int64(params.RefreshTokenLifetime.Round(time.Second).Seconds()),
				int64(params.LoginTokenLifetime.Round(time.Second).Seconds()),
				int64(params.InviteTokenLifetime.Round(time.Second).Seconds()),
				int64(params.VerifyTokenLifetime.Round(time.Second).Seconds()),
				int64(params.AuthCodeLifetime.Round(time.Second).Seconds()),
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

		return h.instanceUpdatePermissions(ctx, &inst, PermissionUpdate{Add: params.Permissions})
	}); err != nil {
		log.Error(err.Error())

		return nil, err
	}

	log.Debugf("instance %s created", inst.ID)

	return h.instanceExpand(ctx, &inst, expandAll)
}

// InstanceUpdate updates an application by id, including child objects
func (h *Hiro) InstanceUpdate(ctx context.Context, params InstanceUpdateInput) (*Instance, error) {
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

		if params.TokenLifetime != nil {
			*params.TokenLifetime = time.Duration(params.TokenLifetime.Round(time.Second).Seconds())
		}

		if params.SessionLifetime != nil {
			*params.SessionLifetime = time.Duration(params.SessionLifetime.Round(time.Second).Seconds())
		}

		if params.RefreshTokenLifetime != nil {
			*params.RefreshTokenLifetime = time.Duration(params.RefreshTokenLifetime.Round(time.Second).Seconds())
		}

		if params.LoginTokenLifetime != nil {
			*params.LoginTokenLifetime = time.Duration(params.LoginTokenLifetime.Round(time.Second).Seconds())
		}

		if params.InviteTokenLifetime != nil {
			*params.InviteTokenLifetime = time.Duration(params.InviteTokenLifetime.Round(time.Second).Seconds())
		}

		if params.VerifyTokenLifetime != nil {
			*params.VerifyTokenLifetime = time.Duration(params.VerifyTokenLifetime.Round(time.Second).Seconds())
		}

		if params.AuthCodeLifetime != nil {
			*params.AuthCodeLifetime = time.Duration(params.AuthCodeLifetime.Round(time.Second).Seconds())
		}

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
			a, err := h.InstanceGet(ctx, InstanceGetInput{
				InstanceID: &params.InstanceID,
			})
			if err != nil {
				return err
			}
			inst = *a
		}

		return h.instanceUpdatePermissions(ctx, &inst, params.Permissions)
	}); err != nil {
		return nil, err
	}

	log.Debugf("instance %s updated", inst.Name)

	return h.instanceExpand(ctx, &inst, expandAll)
}

// InstanceGet gets an instance by id and optionally preloads child objects
func (h *Hiro) InstanceGet(ctx context.Context, params InstanceGetInput) (*Instance, error) {
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
			sq.Eq{"slug": *params.Name},
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

	return h.instanceExpand(ctx, inst, params.Expand)
}

// InstanceList returns a listing of instances
func (h *Hiro) InstanceList(ctx context.Context, params InstanceListInput) ([]*Instance, error) {
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

	for _, inst := range insts {
		if _, err := h.instanceExpand(ctx, inst, params.Expand); err != nil {
			return nil, err
		}
	}

	return insts, nil
}

// InstanceDelete deletes an instance by id
func (h *Hiro) InstanceDelete(ctx context.Context, params InstanceDeleteInput) error {
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

func (h *Hiro) instanceUpdatePermissions(ctx context.Context, inst *Instance, perms PermissionUpdate) error {
	log := Log(ctx).WithField("operation", "instanceUpdatePermissions").WithField("instance", inst.ID)

	db := h.DB(ctx)

	for _, p := range perms.Add {
		_, err := sq.Insert("hiro.instance_permissions").
			Columns("instance_id", "permission", "description").
			Values(
				inst.ID,
				p.Permission,
				p.Description,
			).
			Suffix("ON CONFLICT DO NOTHING").
			RunWith(db).
			PlaceholderFormat(sq.Dollar).
			ExecContext(ctx)
		if err != nil {
			log.Errorf("failed to update instance permissions %s: %s", inst.ID, err)

			return ParseSQLError(err)
		}
	}

	for _, p := range perms.Remove {
		if _, err := sq.Delete("hiro.instance_permissions").
			Where(
				sq.Eq{
					"instance_id": inst.ID,
					"permission":  p.Permission,
				},
			).
			PlaceholderFormat(sq.Dollar).
			RunWith(db).
			ExecContext(ctx); err != nil {
			log.Errorf("failed to delete instance permissions %s: %s", inst.ID, err)

			return ParseSQLError(err)
		}
	}

	return nil
}

func (h *Hiro) instanceExpand(ctx context.Context, inst *Instance, expand common.StringSlice) (*Instance, error) {
	log := Log(ctx).WithField("operation", "instanceExpand").WithField("instance", inst.ID)

	db := h.DB(ctx)

	if expand.ContainsAny("permissions", "*") {
		if err := db.SelectContext(
			ctx,
			&inst.Permissions,
			`SELECT * 
		 FROM hiro.instance_permissions 
		 WHERE instance_id=$1`,
			inst.ID); err != nil {
			log.Errorf("failed to load instance permissions %s: %s", inst.ID, err)

			return nil, ParseSQLError(err)
		}
	}

	if expand.ContainsAny("secrets", "*") {
		if err := db.SelectContext(
			ctx,
			&inst.Secrets,
			`SELECT * 
		 FROM hiro.secrets 
		 WHERE instance_id=$1`,
			inst.ID); err != nil {
			log.Errorf("failed to load instance secrets %s: %s", inst.ID, err)

			return nil, ParseSQLError(err)
		}

		inst.TokenSecrets = make([]oauth.TokenSecret, 0)
		inst.SessionKeys = make([]SessionKey, 0)

		for _, s := range inst.Secrets {
			if s.Type == SecretTypeToken {
				if *s.Algorithm == inst.TokenAlgorithm {
					k, err := TokenSecret(&s)
					if err != nil {
						return nil, err
					}

					inst.TokenSecrets = append(inst.TokenSecrets, k)
				}
			} else {
				inst.SessionKeys = append(inst.SessionKeys, SessionKey(s))
			}
		}
	}

	if expand.ContainsAny("roles", "*") {
		if err := db.SelectContext(
			ctx,
			&inst.Roles,
			`SELECT * 
		 FROM hiro.roles 
		 WHERE instance_id=$1`,
			inst.ID); err != nil {
			log.Errorf("failed to load instance roles %s: %s", inst.ID, err)

			return nil, ParseSQLError(err)
		}
	}

	return inst, nil
}
