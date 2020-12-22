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
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/oauth/openid"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/types"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// User is a hiro user
	User struct {
		ID                types.ID        `json:"id" db:"id"`
		CreatedAt         time.Time       `json:"created_at" db:"created_at"`
		UpdatedAt         *time.Time      `json:"updated_at,omitempty" db:"updated_at"`
		Login             string          `json:"login" db:"login"`
		Password          *string         `json:"-" db:"-"`
		PasswordHash      *string         `json:"-" db:"password_hash,omitempty"`
		PasswordExpiresAt *time.Time      `json:"password_expires_at,omitempty" db:"password_expires_at"`
		LockedUntil       *time.Time      `json:"locked_until,omitempty" db:"locked_until,omitempty"`
		Roles             []string        `json:"roles,omitempty"`
		Permissions       oauth.ScopeSet  `json:"permissions,omitempty" db:"-"`
		Profile           *openid.Profile `json:"profile,omitempty" db:"profile"`
		Metadata          types.Metadata  `json:"metadata,omitempty" db:"metadata"`
	}

	// UserCreateInput is the user create request input
	UserCreateInput struct {
		Login             string          `json:"login"`
		Password          *string         `json:"password,omitempty"`
		Roles             []string        `json:"roles,omitempty"`
		Profile           *openid.Profile `json:"profile,omitempty"`
		PasswordExpiresAt *time.Time      `json:"password_expires_at,omitempty" `
		Metadata          types.Metadata  `json:"metadata,omitempty"`
	}

	// UserUpdateInput is the update user request input
	UserUpdateInput struct {
		UserID            *types.ID       `json:"user_id" structs:"-"`
		Login             *string         `json:"login,omitempty"`
		Password          *string         `json:"password,omitempty" structs:"-"`
		Profile           *openid.Profile `json:"profile,omitempty" structs:"profile,omitempty"`
		PasswordExpiresAt *time.Time      `json:"-" structs:"password_expires_at,omitempty"`
		LockedUntil       *time.Time      `json:"locked_until,omitempty" structs:"-"`
		Roles             []string        `json:"roles,omitempty" structs:"-"`
		Metadata          types.Metadata  `json:"metadata,omitempty" structs:"-"`
	}

	// UserGetInput is used to get an user for the id
	UserGetInput struct {
		UserID *types.ID `json:"user_id,omitempty"`
		Login  *string   `json:"login,omitempty"`
	}

	// UserListInput is the user list request
	UserListInput struct {
		Limit  *uint64 `json:"limit,omitempty"`
		Offset *uint64 `json:"offset,omitempty"`
	}

	// UserDeleteInput is the user delete request input
	UserDeleteInput struct {
		UserID types.ID `json:"user_id"`
	}

	userPatchInput struct {
		User  *User
		Roles []string
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
		validation.Field(&u.UserID, validation.When(u.Login == nil, validation.Required).Else(validation.Nil)),
		validation.Field(&u.Login, validation.When(u.UserID == nil, validation.Required).Else(validation.Nil)),
	)
}

// ValidateWithContext handles validation of the UserGetInput struct
func (u UserGetInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&u,
		validation.Field(&u.UserID, validation.When(u.Login == nil, validation.Required).Else(validation.Nil)),
		validation.Field(&u.Login, validation.When(u.UserID == nil, validation.Required).Else(validation.Nil)),
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
func (b *Backend) UserCreate(ctx context.Context, params UserCreateInput) (*User, error) {
	var user User

	log := b.Log(ctx).WithField("operation", "UserCreate").WithField("login", params.Login)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new user")

		var passwordHash sql.NullString

		if params.Password != nil {
			hash, err := b.passwords.HashPassword(*params.Password)
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

			return parseSQLError(err)
		}

		return b.userPatch(ctx, userPatchInput{&user, params.Roles})
	}); err != nil {
		return nil, err
	}

	log.Debugf("user %s created", user.ID)

	return b.userPreload(ctx, &user)
}

// UserUpdate updates an user by id, including child objects
func (b *Backend) UserUpdate(ctx context.Context, params UserUpdateInput) (*User, error) {
	var user User

	log := b.Log(ctx).WithField("operation", "UserUpdate").WithField("id", params.UserID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating user")

		q := sq.Update("hiro.users").
			PlaceholderFormat(sq.Dollar)

		updates := structs.Map(params)

		if len(params.Metadata) > 0 {
			updates["metadata"] = sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata)
		}

		if params.Profile != nil {
			updates["profile"] = sq.Expr(fmt.Sprintf("COALESCE(profile, '{}') || %s", sq.Placeholders(1)), params.Profile)
		}

		if params.Password != nil {
			hash, err := b.passwords.HashPassword(*params.Password)
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

		if params.UserID != nil {
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

				return parseSQLError(err)
			}
		}

		return b.userPatch(ctx, userPatchInput{&user, params.Roles})
	}); err != nil {
		return nil, err
	}

	log.Debugf("user updated")

	return b.userPreload(ctx, &user)
}

// UserGet gets an user by id and optionally preloads child objects
func (b *Backend) UserGet(ctx context.Context, params UserGetInput) (*User, error) {
	var suffix string

	log := b.Log(ctx).WithField("operation", "UserGet").
		WithField("id", params.UserID).
		WithField("login", params.Login)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)

	if IsTransaction(db) {
		suffix = "FOR UPDATE"
	}

	query := sq.Select("*").
		From("hiro.users").
		PlaceholderFormat(sq.Dollar)

	if params.UserID != nil {
		query = query.Where(sq.Eq{"id": *params.UserID})
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

		return nil, parseSQLError(err)
	}

	user := User{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(&user); err != nil {
		log.Error(err.Error())

		return nil, parseSQLError(err)
	}

	return b.userPreload(ctx, &user)
}

// UserList returns a listing of users
func (b *Backend) UserList(ctx context.Context, params UserListInput) ([]*User, error) {
	log := b.Log(ctx).WithField("operation", "UserList")

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)

	query := sq.Select("*").
		From("hiro.users")

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

	users := make([]*User, 0)
	if err := db.SelectContext(ctx, &users, stmt, args...); err != nil {
		return nil, parseSQLError(err)
	}

	for _, user := range users {
		if _, err = b.userPreload(ctx, user); err != nil {
			return nil, err
		}
	}

	return users, nil
}

// UserDelete deletes an user by id
func (b *Backend) UserDelete(ctx context.Context, params UserDeleteInput) error {
	log := b.Log(ctx).WithField("operation", "UserDelete").WithField("user", params.UserID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)
	if _, err := sq.Delete("hiro.users").
		Where(
			sq.Eq{"id": params.UserID},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to delete user %s: %s", params.UserID, err)
		return parseSQLError(err)
	}

	return nil
}

func (b *Backend) userPatch(ctx context.Context, params userPatchInput) error {
	if len(params.Roles) == 0 {
		return nil
	}

	log := b.Log(ctx).WithField("operation", "userPatch").WithField("user", params.User.ID)

	db := b.DB(ctx)

	if _, err := sq.Delete("hiro.user_roles").
		Where(
			sq.Eq{"user_id": params.User.ID},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to delete roles for user: %s", err)

		return parseSQLError(err)
	}

	for _, role := range params.Roles {
		input := RoleGetInput{
			Preload: ptr.False,
		}

		if roleID := types.ID(role); roleID.Valid() {
			input.RoleID = &roleID
		} else {
			input.Name = &role
		}

		r, err := b.RoleGet(ctx, input)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errors.New("role not found")
			}
			return err
		}

		if _, err := sq.Insert("hiro.user_roles").
			Columns("user_id", "role_id").
			Values(
				params.User.ID,
				r.ID,
			).
			Suffix("ON CONFLICT DO NOTHING").
			RunWith(db).
			PlaceholderFormat(sq.Dollar).
			ExecContext(ctx); err != nil {
			log.Errorf("failed to update user permissions: %s", err)

			return parseSQLError(err)
		}

		params.User.Roles = params.Roles
	}

	return nil
}

func (b *Backend) userPreload(ctx context.Context, user *User) (*User, error) {
	log := b.Log(ctx).WithField("operation", "userPreload").WithField("user", user.ID)

	db := b.DB(ctx)

	perms := []struct {
		Audience   string `db:"audience"`
		Permission string `db:"permission"`
	}{}

	if err := db.SelectContext(
		ctx,
		&user.Roles,
		`SELECT R.slug
		 FROM hiro.user_roles u
		 LEFT JOIN hiro.roles R
			 ON  u.role_id = r.id
		 WHERE u.user_id=$1`,
		user.ID); err != nil {
		log.Errorf("failed to load user roles %s: %s", user.ID, err)

		return nil, parseSQLError(err)
	}

	if err := db.SelectContext(
		ctx,
		&perms,
		`SELECT a.name as audience, p.permission
		 FROM hiro.user_roles r 
		 LEFT JOIN hiro.role_permissions p
		 	ON p.role_id = r.role_id
		 LEFT JOIN hiro.audiences a
			 ON  a.id = p.audience_id
		 WHERE r.user_id=$1`,
		user.ID); err != nil {
		log.Errorf("failed to load user permissions %s: %s", user.ID, err)

		return nil, parseSQLError(err)
	}

	user.Permissions = make(oauth.ScopeSet)
	for _, p := range perms {
		user.Permissions.Append(p.Audience, p.Permission)
	}

	return user, nil
}
