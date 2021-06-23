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
		ID              ID                   `json:"id" db:"id"`
		Name            string               `json:"name" db:"name"`
		Slug            string               `json:"slug" db:"slug"`
		Audience        *string              `json:"audience,omitempty" db:"audience"`
		Description     *string              `json:"description,omitempty" db:"description"`
		TokenSecrets    []oauth.TokenSecret  `json:"-" db:"-"`
		SessionKeys     []SessionKey         `json:"-" db:"-"`
		Secrets         []*Secret            `json:"secrets,omitempty" db:"-"`
		TokenAlgorithm  oauth.TokenAlgorithm `json:"token_algorithm" db:"token_algorithm"`
		TokenLifetime   time.Duration        `json:"token_lifetime" db:"token_lifetime"`
		SessionLifetime time.Duration        `json:"session_lifetime,omitempty" db:"session_lifetime"`
		CreatedAt       time.Time            `json:"created_at" db:"created_at"`
		UpdatedAt       *time.Time           `json:"updated_at,omitempty" db:"updated_at"`
		Permissions     oauth.Scope          `json:"permissions,omitempty" db:"-"`
		Metadata        common.Map           `json:"metadata,omitempty" db:"metadata"`
	}

	// InstanceInitializeInput is the input to the instance initialization
	InstanceInitializeInput struct {
		Name            string                `json:"name"`
		Description     *string               `json:"description,omitempty"`
		Audience        *string               `json:"audience,omitempty" db:"audience"`
		TokenLifetime   *time.Duration        `json:"token_lifetime"`
		TokenAlgorithm  *oauth.TokenAlgorithm `json:"token_algorithm"`
		SessionLifetime *time.Duration        `json:"session_lifetime,omitempty"`
		Permissions     oauth.Scope           `json:"permissions,omitempty"`
		Metadata        common.Map            `json:"metadata,omitempty"`
		Roles           oauth.ScopeSet        `json:"roles,omitempty"`
	}

	// InstanceCreateInput is the instance create request
	InstanceCreateInput struct {
		Name            string               `json:"name"`
		Description     *string              `json:"description,omitempty"`
		Audience        *string              `json:"audience,omitempty" db:"audience"`
		TokenLifetime   time.Duration        `json:"token_lifetime"`
		TokenAlgorithm  oauth.TokenAlgorithm `json:"token_algorithm"`
		SessionLifetime time.Duration        `json:"session_lifetime,omitempty"`
		Permissions     oauth.Scope          `json:"permissions,omitempty"`
		Metadata        common.Map           `json:"metadata,omitempty"`
	}

	// InstanceUpdateInput is the instance update request
	InstanceUpdateInput struct {
		InstanceID      ID                         `json:"instance_id" structs:"-"`
		Name            *string                    `json:"name" structs:"name,omitempty"`
		Description     *string                    `json:"description,omitempty" structs:"description,omitempty"`
		Audience        *string                    `json:"audience,omitempty" structs:"audience,omitempty"`
		TokenAlgorithm  *oauth.TokenAlgorithm      `json:"token_algorithm,omitempty" structs:"token_algorithm,omitempty"`
		TokenLifetime   *time.Duration             `json:"token_lifetime" structs:"token_lifetime,omitempty"`
		SessionLifetime *time.Duration             `json:"session_lifetime,omitempty" structs:"session_lifetime,omitempty"`
		Permissions     *InstancePermissionsUpdate `json:"permissions,omitempty" structs:"-"`
		Metadata        common.Map                 `json:"metadata,omitempty" structs:"-"`
	}

	// InstancePermissionsUpdate is used to update instance permissions
	InstancePermissionsUpdate struct {
		Add       oauth.Scope `json:"add,omitempty"`
		Remove    oauth.Scope `json:"remove,omitempty"`
		Overwrite bool        `json:"overrite"`
	}

	// InstanceGetInput is used to get an instance for the id
	InstanceGetInput struct {
		InstanceID *ID     `json:"instance_id,omitempty"`
		Name       *string `json:"name,omitempty"`
		Domain     *string `json:"domain,omitempty"`
	}

	// InstanceListInput is the instance list request
	InstanceListInput struct {
		Limit  *uint64 `json:"limit,omitempty"`
		Offset *uint64 `json:"offset,omitempty"`
		Count  *uint64 `json:"count,omitempty"`
	}

	// InstanceDeleteInput is the instance delete request input
	InstanceDeleteInput struct {
		InstanceID ID `json:"instance_id"`
	}
)

// ValidateWithContext handles validation of the InstanceInitializeInput struct
func (a InstanceInitializeInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.Name, validation.Required, validation.Length(3, 64)),
		validation.Field(&a.Permissions, validation.NilOrNotEmpty),
	)
}

// ValidateWithContext handles validation of the InstanceCreateInput struct
func (a InstanceCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.Name, validation.Required, validation.Length(3, 64)),
		validation.Field(&a.Audience, validation.Required, is.Domain),
		validation.Field(&a.Permissions, validation.Required),
		validation.Field(&a.TokenAlgorithm, validation.Required),
		validation.Field(&a.TokenLifetime, validation.Required),
		validation.Field(&a.SessionLifetime, validation.Required),
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

// InstanceInitialize will create or update and instance, intialize a default application and secrets
func (b *Hiro) InstanceInitialize(ctx context.Context, params InstanceInitializeInput) (*Instance, error) {
	var inst *Instance
	var err error

	log := Log(ctx).WithField("operation", "InstanceInitialize").WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if params.TokenAlgorithm == nil {
		params.TokenAlgorithm = DefaultTokenAlgorithm.Ptr()
	}

	if params.TokenLifetime == nil {
		params.TokenLifetime = ptr.Duration(DefaultTokenLifetime)
	}

	if params.SessionLifetime == nil {
		params.SessionLifetime = ptr.Duration(DefaultSessionLifetime)
	}

	if params.Permissions == nil {
		params.Permissions = make(oauth.Scope, 0)
	}

	// always include hiro and oauth scopes
	params.Permissions = append(params.Permissions, Scopes...)
	params.Permissions = append(params.Permissions, oauth.Scopes...)
	params.Permissions = params.Permissions.Unique()

	// do the initialization in a single transaction
	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		inst, err = b.InstanceCreate(ctx, InstanceCreateInput{
			Name:            params.Name,
			Description:     params.Description,
			Audience:        params.Audience,
			TokenLifetime:   params.TokenLifetime.Round(time.Second),
			TokenAlgorithm:  *params.TokenAlgorithm,
			SessionLifetime: *params.SessionLifetime,
			Metadata:        params.Metadata,
			Permissions:     params.Permissions,
		})
		if err != nil && !errors.Is(err, ErrDuplicateObject) {
			return err
		}

		// ensure the permissions are consistent
		if _, err := b.InstanceUpdate(ctx, InstanceUpdateInput{
			InstanceID: inst.ID,
			Permissions: &InstancePermissionsUpdate{
				Add: params.Permissions,
			},
		}); err != nil {
			return err
		}

		log.Infof("instance %s [%s] initialized", inst.Name, inst.ID)

		// generate secrets is none exist
		if len(inst.TokenSecrets) == 0 {
			if _, err := b.SecretCreate(ctx, SecretCreateInput{
				InstanceID: inst.ID,
				Type:       SecretTypeToken,
				Algorithm:  &inst.TokenAlgorithm,
			}); err != nil {
				return fmt.Errorf("%w: failed to create instance token secret", err)
			}
		}

		// generate a session key if none exists
		if len(inst.SessionKeys) == 0 {
			if _, err := b.SecretCreate(ctx, SecretCreateInput{
				InstanceID: inst.ID,
				Type:       SecretTypeSession,
			}); err != nil {
				return fmt.Errorf("%w: failed to create instance session key", err)
			}
		}

		// create a new application for the instance
		app, err := b.ApplicationCreate(ctx, ApplicationCreateInput{
			Name: inst.Name,
			Type: oauth.ClientTypeMachine,
			Permissions: oauth.ScopeSet{
				inst.Name: inst.Permissions,
				"hiro":    append(Scopes, oauth.Scopes...),
			},
			Grants: oauth.Grants{
				inst.Name: {oauth.GrantTypeClientCredentials, oauth.GrantTypeAuthCode, oauth.GrantTypeRefreshToken},
				"hiro":    {oauth.GrantTypeClientCredentials, oauth.GrantTypeAuthCode, oauth.GrantTypeRefreshToken},
			},
		})
		if err != nil && !errors.Is(err, ErrDuplicateObject) {
			return err
		}
		if _, err := b.ApplicationUpdate(ctx, ApplicationUpdateInput{
			ApplicationID: app.ID,
			Grants: oauth.Grants{
				inst.Name: {oauth.GrantTypeClientCredentials, oauth.GrantTypeAuthCode, oauth.GrantTypeRefreshToken},
				"hiro":    {oauth.GrantTypeClientCredentials, oauth.GrantTypeAuthCode, oauth.GrantTypeRefreshToken},
			},
			Permissions: &PermissionUpdate{
				Add: oauth.ScopeSet{
					inst.Name: inst.Permissions,
					"hiro":    append(Scopes, oauth.Scopes...),
				},
			},
		}); err != nil {
			return err
		}

		for r, p := range params.Roles {
			role, err := b.RoleCreate(ctx, RoleCreateInput{
				InstanceID: inst.ID,
				Name:       r,
				Permissions: oauth.ScopeSet{
					inst.Slug: p,
				},
			})
			if err != nil && !errors.Is(err, ErrDuplicateObject) {
				return err
			}

			if _, err := b.RoleUpdate(ctx, RoleUpdateInput{
				RoleID: role.ID,
				Permissions: &PermissionUpdate{
					Add: oauth.ScopeSet{
						inst.Slug: p,
					},
				},
			}); err != nil {
				return err
			}
		}

		log.Infof("application %s initialized, client_id = %q, client_secret=%q", app.Slug, app.ID, safe.String(app.SecretKey))

		// return a txcommit error to ensure the transaction is committed
		return ErrTxCommit(nil)
	}, ErrDuplicateObject); err != nil {
		return nil, err
	}

	return inst, nil
}

// InstanceCreate create a new permission object
func (b *Hiro) InstanceCreate(ctx context.Context, params InstanceCreateInput) (*Instance, error) {
	var inst Instance

	log := Log(ctx).WithField("operation", "InstanceCreate").WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new instance")

		stmt, args, err := sq.Insert("hiro.instances").
			Columns(
				"name",
				"description",
				"domain",
				"token_algorithm",
				"token_lifetime",
				"session_lifetime",
				"metadata").
			Values(
				params.Name,
				null.String(params.Description),
				null.String(params.Audience),
				params.TokenAlgorithm,
				params.TokenLifetime.Round(time.Second),
				params.SessionLifetime,
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

		return b.instanceUpdatePermissions(ctx, &inst, &InstancePermissionsUpdate{Add: params.Permissions})
	}); err != nil {
		if errors.Is(err, ErrDuplicateObject) {
			return b.InstanceGet(ctx, InstanceGetInput{
				Name: &params.Name,
			})
		}

		log.Error(err.Error())

		return nil, err
	}

	log.Debugf("instance %s created", inst.ID)

	return &inst, nil
}

// InstanceUpdate updates an application by id, including child objects
func (b *Hiro) InstanceUpdate(ctx context.Context, params InstanceUpdateInput) (*Instance, error) {
	var inst Instance

	log := Log(ctx).WithField("operation", "InstanceUpdate").WithField("id", params.InstanceID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating instance")

		q := sq.Update("hiro.instances").
			PlaceholderFormat(sq.Dollar)

		if params.TokenLifetime != nil {
			*params.TokenLifetime = params.TokenLifetime.Round(time.Second)
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
			a, err := b.InstanceGet(ctx, InstanceGetInput{
				InstanceID: &params.InstanceID,
			})
			if err != nil {
				return err
			}
			inst = *a
		}

		return b.instanceUpdatePermissions(ctx, &inst, params.Permissions)
	}); err != nil {
		return nil, err
	}

	log.Debugf("instance %s updated", inst.Name)

	return &inst, b.instancePreload(ctx, &inst)
}

// InstanceGet gets an instance by id and optionally preloads child objects
func (b *Hiro) InstanceGet(ctx context.Context, params InstanceGetInput) (*Instance, error) {
	var suffix string

	log := Log(ctx).WithField("operation", "InstanceGet").WithField("params", params)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)

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
	} else if params.Domain != nil {
		query = query.Where(sq.Or{
			sq.Eq{"domain": *params.Domain},
			sq.Expr("? ~ domain", *params.Domain),
		})
	} else {
		return nil, fmt.Errorf("%w: instance id, name, or domain required", ErrInputValidation)
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

	return inst, b.instancePreload(ctx, inst)
}

// InstanceList returns a listing of instances
func (b *Hiro) InstanceList(ctx context.Context, params InstanceListInput) ([]*Instance, error) {
	log := Log(ctx).WithField("operation", "InstanceList")

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)

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

	auds := make([]*Instance, 0)
	if err := db.SelectContext(ctx, &auds, stmt, args...); err != nil {
		return nil, ParseSQLError(err)
	}

	for _, inst := range auds {
		if err := b.instancePreload(ctx, inst); err != nil {
			return nil, err
		}
	}

	return auds, nil
}

// InstanceDelete deletes an instance by id
func (b *Hiro) InstanceDelete(ctx context.Context, params InstanceDeleteInput) error {
	log := Log(ctx).WithField("operation", "InstanceDelete").WithField("instance", params.InstanceID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)
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

func (b *Hiro) instanceUpdatePermissions(ctx context.Context, inst *Instance, perms *InstancePermissionsUpdate) error {
	log := Log(ctx).WithField("operation", "instanceUpdatePermissions").WithField("instance", inst.ID)

	if perms == nil {
		return nil
	}

	if len(perms.Add) == 0 && len(perms.Remove) == 0 {
		return nil
	}

	db := b.DB(ctx)

	if perms.Overwrite {
		if _, err := sq.Delete("hiro.instance_permissions").
			Where(
				sq.Eq{"instance_id": inst.ID},
			).
			PlaceholderFormat(sq.Dollar).
			RunWith(db).
			ExecContext(ctx); err != nil {
			log.Errorf("failed to delete instance permissions %s: %s", inst.ID, err)

			return ParseSQLError(err)
		}
	}

	for _, p := range perms.Add.Unique() {
		_, err := sq.Insert("hiro.instance_permissions").
			Columns("instance_id", "permission").
			Values(
				inst.ID,
				p,
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

	for _, p := range perms.Remove.Unique() {
		if _, err := sq.Delete("hiro.instance_permissions").
			Where(
				sq.Eq{"instance_id": inst.ID},
				sq.Eq{"permission": p},
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

func (b *Hiro) instancePreload(ctx context.Context, inst *Instance) error {
	log := Log(ctx).WithField("operation", "instancePreload").WithField("instance", inst.ID)

	db := b.DB(ctx)

	if err := db.SelectContext(
		ctx,
		&inst.Permissions,
		`SELECT permission 
		 FROM hiro.instance_permissions 
		 WHERE instance_id=$1`,
		inst.ID); err != nil {
		log.Errorf("failed to load instance permissions %s: %s", inst.ID, err)

		return ParseSQLError(err)
	}

	if err := db.SelectContext(
		ctx,
		&inst.Secrets,
		`SELECT * 
		 FROM hiro.secrets 
		 WHERE instance_id=$1`,
		inst.ID); err != nil {
		log.Errorf("failed to load instance secrets %s: %s", inst.ID, err)

		return ParseSQLError(err)
	}

	inst.TokenSecrets = make([]oauth.TokenSecret, 0)
	inst.SessionKeys = make([]SessionKey, 0)

	for _, s := range inst.Secrets {
		if s.Type == SecretTypeToken {
			if *s.Algorithm == inst.TokenAlgorithm {
				k, err := TokenSecret(s)
				if err != nil {
					return err
				}

				inst.TokenSecrets = append(inst.TokenSecrets, k)
			}
		} else {
			inst.SessionKeys = append(inst.SessionKeys, SessionKey(*s))
		}
	}

	return nil
}
