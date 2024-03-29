/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://githuh.com/ModelRocket/hiro
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
	"database/sql"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/ModelRocket/hiro/pkg/common"
	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/ModelRocket/hiro/pkg/oauth/openid"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// UserController is the user API interface
	UserController interface {
		UserCreate(ctx context.Context, params UserCreateInput) (*User, error)
		UserGet(ctx context.Context, params UserGetInput) (*User, error)
		UserList(ctx context.Context, params UserListInput) ([]*User, error)
		UserUpdate(ctx context.Context, params UserUpdateInput) (*User, error)
		UserDelete(ctx context.Context, params UserDeleteInput) error
	}

	// User is a hiro user
	User struct {
		ID                ID              `json:"id" db:"id"`
		CreatedAt         time.Time       `json:"created_at" db:"created_at"`
		UpdatedAt         *time.Time      `json:"updated_at,omitempty" db:"updated_at"`
		Login             string          `json:"login" db:"login"`
		PasswordHash      *string         `json:"-" db:"password_hash,omitempty"`
		PasswordExpiresAt *time.Time      `json:"password_expires_at,omitempty" db:"password_expires_at"`
		LockedUntil       *time.Time      `json:"locked_until,omitempty" db:"locked_until,omitempty"`
		Roles             []Role          `json:"roles,omitempty"`
		Profile           *openid.Profile `json:"profile,omitempty" db:"profile"`
		Metadata          common.Map      `json:"metadata,omitempty" db:"metadata"`
	}

	// UserPermission is a user permission entry
	UserPermission struct {
		InstanceID ID     `json:"instance_id"`
		Permission string `json:"permission"`
	}

	// UserCreateInput is the user create request input
	UserCreateInput struct {
		InstanceID        ID              `json:"instance_id"`
		Login             string          `json:"login"`
		Password          *string         `json:"password,omitempty"`
		Roles             []UserRole      `json:"roles,omitempty"`
		Profile           *openid.Profile `json:"profile,omitempty"`
		PasswordExpiresAt *time.Time      `json:"password_expires_at,omitempty" `
		Metadata          common.Map      `json:"metadata,omitempty"`
	}

	// UserRole is used to add roles to a user
	UserRole struct {
		InstanceID ID      `json:"instance_id"`
		RoleID     *ID     `json:"role_id,omitempty"`
		Role       *string `json:"role,omitempty"`
	}

	// UserUpdateInput is the update user request input
	UserUpdateInput struct {
		UserID            ID              `json:"user_id" structs:"-"`
		Login             *string         `json:"login,omitempty"`
		Password          *string         `json:"password,omitempty" structs:"-"`
		Profile           *openid.Profile `json:"profile,omitempty" structs:"profile,omitempty"`
		PasswordExpiresAt *time.Time      `json:"-" structs:"password_expires_at,omitempty"`
		LockedUntil       *time.Time      `json:"locked_until,omitempty" structs:"-"`
		Roles             RoleUpdate      `json:"roles,omitempty" structs:"-"`
		Metadata          common.Map      `json:"metadata,omitempty" structs:"-"`
	}

	// RoleUpdate is used to update roles of a user
	RoleUpdate struct {
		Add    []UserRole `json:"add,omitempty"`
		Remove []UserRole `json:"remove,omitempty"`
	}

	// UserGetInput is used to get an user for the id
	UserGetInput struct {
		InstanceID *ID                `json:"instance_id,omitempty"`
		UserID     ID                 `json:"user_id,omitempty"`
		Expand     common.StringSlice `json:"expand,omitempty"`
		Login      *string            `json:"-"`
	}

	// UserListInput is the user list request
	UserListInput struct {
		InstanceID *ID                `json:"instance_id,omitempty"`
		Expand     common.StringSlice `json:"expand,omitempty"`
		Limit      *uint64            `json:"limit,omitempty"`
		Offset     *uint64            `json:"offset,omitempty"`
		Count      *uint64            `json:"count,omitempty"`
	}

	// UserDeleteInput is the user delete request input
	UserDeleteInput struct {
		InstanceID *ID `json:"instance_id,omitempty"`
		UserID     ID  `json:"user_id"`
	}

	userPatchInput struct {
		User  *User
		Roles RoleUpdate
	}
)

// ValidateWithContext handles validation of the UserCreateInput struct
func (u UserCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&u,
		validation.Field(&u.Login, validation.Required),
		validation.Field(&u.Roles, validation.NilOrNotEmpty),
	)
}

// ValidateWithContext handles validation of the UserCreateInput struct
func (u UserUpdateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&u,
		validation.Field(&u.UserID, validation.When(u.Login == nil, validation.Required).Else(validation.Empty)),
		validation.Field(&u.Login, validation.When(!u.UserID.Valid(), validation.Required).Else(validation.Nil)),
	)
}

// ValidateWithContext handles validation of the UserGetInput struct
func (u UserGetInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&u,
		validation.Field(&u.UserID, validation.When(u.Login == nil, validation.Required).Else(validation.Empty)),
		validation.Field(&u.Login, validation.When(!u.UserID.Valid(), validation.Required).Else(validation.Nil)),
	)
}

// ValidateWithContext handles validation of the UserListInput struct
func (u UserListInput) ValidateWithContext(context.Context) error {
	return nil
}

// ValidateWithContext handles validation of the UserDeleteInput
func (u UserDeleteInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&u,
		validation.Field(&u.UserID, validation.Required),
	)
}

// UserCreate create a new permission object
func (h *Hiro) UserCreate(ctx context.Context, params UserCreateInput) (*User, error) {
	var user User

	log := Log(ctx).WithField("operation", "UserCreate").WithField("login", params.Login)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new user")

		var passwordHash sql.NullString

		if params.Password != nil {
			hash, err := h.passwords.HashPassword(*params.Password)
			if err != nil {
				return err
			}

			passwordHash.String = hash
			passwordHash.Valid = true
		}

		stmt, args, err := sq.Insert("hiro.users").
			Columns(
				"login",
				"password_hash",
				"password_expires_at",
				"profile",
				"metadata").
			Values(
				params.Login,
				passwordHash,
				null.Time(params.PasswordExpiresAt),
				null.JSON(params.Profile),
				null.JSON(params.Metadata),
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(`RETURNING *`).
			ToSql()
		if err != nil {
			log.Error(err.Error())

			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &user, stmt, args...); err != nil {
			log.Error(err.Error())

			return ParseSQLError(err)
		}

		return h.userPatch(ctx, userPatchInput{
			User:  &user,
			Roles: RoleUpdate{Add: params.Roles},
		})
	}); err != nil {
		return nil, err
	}

	log.Debugf("user %s created", user.ID)

	return h.userExpand(ctx, &user, ExpandAll)
}

// UserUpdate updates an user by id, including child objects
func (h *Hiro) UserUpdate(ctx context.Context, params UserUpdateInput) (*User, error) {
	var user User

	log := Log(ctx).WithField("operation", "UserUpdate").WithField("id", params.UserID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating user")

		q := sq.Update("hiro.users").
			PlaceholderFormat(sq.Dollar)

		updates := structs.Map(params)

		if params.Metadata != nil {
			updates["metadata"] = sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata)
		}

		if params.Profile != nil {
			updates["profile"] = sq.Expr(fmt.Sprintf("COALESCE(profile, '{}') || %s", sq.Placeholders(1)), params.Profile)
		}

		if params.Password != nil {
			hash, err := h.passwords.HashPassword(*params.Password)
			if err != nil {
				return err
			}
			updates["password_hash"] = hash
		}

		if params.LockedUntil != nil {
			if params.LockedUntil.IsZero() {
				updates["locked_until"] = sql.NullTime{}
			} else {
				updates["locked_until"] = *params.LockedUntil
			}
		}

		if params.UserID.Valid() {
			q = q.Where(sq.Eq{"id": params.UserID})
		} else if params.Login != nil {
			q = q.Where(sq.Eq{"login": params.Login})
		}

		if len(updates) > 0 {
			stmt, args, err := q.SetMap(updates).
				Suffix("RETURNING *").
				ToSql()
			if err != nil {
				log.Error(err.Error())

				return fmt.Errorf("%w: failed to build query statement", err)
			}

			if err := tx.GetContext(ctx, &user, stmt, args...); err != nil {
				log.Error(err.Error())

				return ParseSQLError(err)
			}
		}

		return h.userPatch(ctx, userPatchInput{
			User:  &user,
			Roles: params.Roles,
		})
	}); err != nil {
		return nil, err
	}

	log.Debugf("user updated")

	return h.userExpand(ctx, &user, ExpandAll)
}

// UserGet gets an user by id and optionally preloads child objects
func (h *Hiro) UserGet(ctx context.Context, params UserGetInput) (*User, error) {
	var suffix string

	log := Log(ctx).WithField("operation", "UserGet").
		WithField("id", params.UserID).
		WithField("login", params.Login)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

	query := sq.Select("*").
		From("hiro.users").
		PlaceholderFormat(sq.Dollar)

	if params.UserID.Valid() {
		query = query.Where(sq.Eq{"id": params.UserID})
	} else if params.Login != nil {
		query = query.Where(sq.Eq{"login": *params.Login})
	} else {
		return nil, fmt.Errorf("%w: user id or login required", ErrInputValidation)
	}

	stmt, args, err := query.
		Suffix(suffix).
		ToSql()
	if err != nil {
		log.Error(err.Error())

		return nil, ParseSQLError(err)
	}

	user := User{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(&user); err != nil {
		log.Error(err.Error())

		return nil, ParseSQLError(err)
	}

	return h.userExpand(ctx, &user, params.Expand)
}

// UserList returns a listing of users
func (h *Hiro) UserList(ctx context.Context, params UserListInput) ([]*User, error) {
	log := Log(ctx).WithField("operation", "UserList")

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
		From("hiro.users")

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

	users := make([]*User, 0)
	if err := db.SelectContext(ctx, &users, stmt, args...); err != nil {
		return nil, ParseSQLError(err)
	}

	for _, user := range users {
		if _, err = h.userExpand(ctx, user, params.Expand); err != nil {
			return nil, err
		}
	}

	return users, nil
}

// UserDelete deletes an user by id
func (h *Hiro) UserDelete(ctx context.Context, params UserDeleteInput) error {
	log := Log(ctx).WithField("operation", "UserDelete").WithField("user", params.UserID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)
	if _, err := sq.Delete("hiro.users").
		Where(
			sq.Eq{"id": params.UserID},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to delete user %s: %s", params.UserID, err)
		return ParseSQLError(err)
	}

	return nil
}

func (h *Hiro) userPatch(ctx context.Context, params userPatchInput) error {

	log := Log(ctx).WithField("operation", "userPatch").WithField("user", params.User.ID)

	db := h.DB(ctx)

	for _, r := range params.Roles.Add {
		if r.RoleID == nil {
			role, err := h.RoleGet(ctx, RoleGetInput{
				InstanceID: r.InstanceID,
				Name:       r.Role,
			})
			if err != nil {
				return err
			}

			r.RoleID = &role.ID
		}

		if _, err := sq.Insert("hiro.user_roles").
			Columns("user_id", "role_id").
			Values(
				params.User.ID,
				r.RoleID,
			).
			Suffix("ON CONFLICT DO NOTHING").
			RunWith(db).
			PlaceholderFormat(sq.Dollar).
			ExecContext(ctx); err != nil {
			log.Errorf("failed to update user permissions: %s", err)

			return ParseSQLError(err)
		}
	}

	for _, r := range params.Roles.Remove {
		if r.RoleID == nil {
			role, err := h.RoleGet(ctx, RoleGetInput{
				InstanceID: r.InstanceID,
				Name:       r.Role,
			})
			if err != nil {
				return err
			}

			r.RoleID = &role.ID
		}

		if _, err := sq.Delete("hiro.user_roles").
			Where(sq.Eq{
				"user_id": params.User.ID,
				"role_id": r.RoleID,
			}).
			RunWith(db).
			PlaceholderFormat(sq.Dollar).
			ExecContext(ctx); err != nil {
			log.Errorf("failed to update user permissions: %s", err)

			return ParseSQLError(err)
		}
	}

	return nil
}

func (h *Hiro) userExpand(ctx context.Context, user *User, expand common.StringSlice) (*User, error) {
	log := Log(ctx).WithField("operation", "userExpand").WithField("user", user.ID)

	db := h.DB(ctx)

	if expand.ContainsAny("roles", "roles.permissions", "*") {
		if err := db.SelectContext(
			ctx,
			&user.Roles,
			`SELECT R.*
		 FROM hiro.user_roles u
		 LEFT JOIN hiro.roles R
			 ON u.role_id = r.id
		 WHERE u.user_id=$1`,
			user.ID); err != nil {
			log.Errorf("failed to load user roles %s: %s", user.ID, err)

			return nil, ParseSQLError(err)
		}
	}

	if expand.ContainsAny("roles.permissions", "*") {
		for i, r := range user.Roles {
			r, err := h.roleExpand(ctx, &r, expand.FilterPrefix("roles"))
			if err != nil {
				return nil, err
			}

			user.Roles[i] = *r
		}
	}

	return user, nil
}
