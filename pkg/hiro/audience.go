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
	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/types"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/gosimple/slug"
)

type (
	// Audience is the database model for an audience
	Audience struct {
		ID             types.ID          `json:"id" db:"id"`
		Name           string            `json:"name" db:"name"`
		Description    *string           `json:"description,omitempty" db:"description"`
		TokenLifetime  time.Duration     `json:"token_lifetime" db:"token_lifetime"`
		TokenAlgorithm TokenAlgorithm    `json:"token_algorithm" db:"token_algorithm"`
		TokenSecret    TokenSecret       `json:"token_secret,omitempty" db:"token_secret"`
		CreatedAt      time.Time         `json:"created_at" db:"created_at"`
		UpdatedAt      *time.Time        `json:"updated_at,omitempty" db:"updated_at"`
		Metadata       types.Metadata    `json:"metadata,omitempty" db:"metadata"`
		Permissions    oauth.Permissions `json:"permissions,omitempty" db:"permissions"`
	}

	// AudienceCreateInput is the audience create request
	AudienceCreateInput struct {
		Name           string            `json:"name"`
		Description    *string           `json:"description,omitempty"`
		TokenLifetime  time.Duration     `json:"token_lifetime,omitempty"`
		TokenAlgorithm TokenAlgorithm    `json:"token_algorithm,omitempty"`
		TokenSecret    TokenSecret       `json:"token_secret,omitempty"`
		Permissions    oauth.Permissions `json:"permissions,omitempty"`
		Metadata       Metadata          `json:"metadata,omitempty"`
	}

	// AudienceGetInput is used to get an audience for the id
	AudienceGetInput struct {
		AudienceID *types.ID `json:"audience_id,omitempty"`
		Name       *string   `json:"name,omitempty"`
		Preload    bool      `json:"preload"`
	}

	// TokenAlgorithm is a token algorithm type
	TokenAlgorithm string
)

const (
	// TokenLifetimeMinimum is the minimum token lifetime
	TokenLifetimeMinimum = time.Minute

	// TokenAlgorithmRS256 is the RSA 256 token algorithm
	TokenAlgorithmRS256 TokenAlgorithm = "RS256"

	// TokenAlgorithmHS256 is the HMAC with SHA-256 token algorithm
	TokenAlgorithmHS256 TokenAlgorithm = "HS256"
)

// ValidateWithContext handles validation of the AudienceCreateInput struct
func (a AudienceCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.Name, validation.Length(3, 64)),
		validation.Field(&a.TokenLifetime, validation.Required, validation.Min(TokenLifetimeMinimum)),
		validation.Field(&a.TokenAlgorithm, validation.Required),
		validation.Field(&a.TokenSecret, validation.Required),
		validation.Field(&a.Permissions, validation.Required),
	)
}

// ValidateWithContext handles validation of the AudienceGetInput struct
func (a AudienceGetInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.AudienceID, validation.When(a.Name == nil, validation.Required).Else(validation.Nil)),
		validation.Field(&a.Name, validation.When(a.AudienceID == nil, validation.Required).Else(validation.Nil)),
	)
}

// ValidateWithContext handles validation for TokenAlgorithm types
func (a TokenAlgorithm) ValidateWithContext(ctx context.Context) error {
	return validation.Validate(string(a), validation.In(TokenAlgorithmRS256, TokenAlgorithmHS256))
}

// AudienceCreate create a new permission object
func (h *Hiro) AudienceCreate(ctx context.Context, params AudienceCreateInput) (*Audience, error) {
	var aud Audience

	if err := params.ValidateWithContext(ctx); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		stmt, args, err := sq.Insert("audiences").
			Columns(
				"name",
				"description",
				"token_lifetime",
				"token_algorithm",
				"token_secret",
				"permissions",
				"metadata").
			Values(
				slug.Make(params.Name),
				null.String(params.Description),
				params.TokenLifetime,
				params.TokenAlgorithm,
				params.TokenSecret,
				params.Permissions,
				null.JSON(params.Metadata),
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(`
			ON CONFLICT (name) DO UPDATE SET description=?, token_lifetime=?, permissions=?, metadata=? RETURNING *`,
				null.String(params.Description),
				params.TokenLifetime,
				params.Permissions,
				null.JSON(params.Metadata),
			).
			ToSql()
		if err != nil {
			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &aud, stmt, args...); err != nil {
			return parseSQLError(err)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return &aud, nil
}

// AudienceGet gets an audience by id and optionally preloads child objects
func (h *Hiro) AudienceGet(ctx context.Context, params AudienceGetInput) (*Audience, error) {
	var suffix string

	if err := params.ValidateWithContext(ctx); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

	if IsTransaction(db) {
		suffix = "FOR UPDATE"
	}

	query := sq.Select("*").
		From("audiences").
		PlaceholderFormat(sq.Dollar)

	if params.AudienceID != nil {
		query = query.Where(sq.Eq{"id": *params.AudienceID})
	} else if params.Name != nil {
		query = query.Where(sq.Eq{"name": *params.Name})
	} else {
		return nil, fmt.Errorf("%w: audience id or name required", ErrInputValidation)
	}

	stmt, args, err := query.
		Suffix(suffix).
		ToSql()
	if err != nil {
		return nil, parseSQLError(err)
	}

	aud := &Audience{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(aud); err != nil {
		return nil, parseSQLError(err)
	}

	if params.Preload {
		if err := aud.Preload(h.Context(ctx)); err != nil {
			return nil, err
		}
	}

	return aud, nil
}

// Preload preloads the audience child objects from the database
func (a *Audience) Preload(ctx context.Context) error {
	h := FromContext(ctx)
	if h == nil {
		return ErrNotFound
	}

	db := h.DB(ctx)

	if err := db.SelectContext(
		ctx,
		&a.Permissions,
		`SELECT * 
		 FROM audience_permissions 
		 WHERE audience_id=$1`,
		a.ID); err != nil {
		return parseSQLError(err)
	}

	return nil
}
