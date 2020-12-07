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
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/types"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/gosimple/slug"
)

type (
	// Audience is the database model for an audience
	Audience struct {
		ID          types.ID       `json:"id" db:"id"`
		Name        string         `json:"name" db:"name"`
		Description *string        `json:"description,omitempty" db:"description"`
		TokenSecret *oauth.Token   `json:"token,omitempty" db:"token"`
		CreatedAt   time.Time      `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time     `json:"updated_at,omitempty" db:"updated_at"`
		Permissions oauth.ScopeList    `json:"permissions,omitempty" db:"permissions"`
		Metadata    types.Metadata `json:"metadata,omitempty" db:"metadata"`
	}

	// AudienceCreateInput is the audience create request
	AudienceCreateInput struct {
		Name        string         `json:"name"`
		Description *string        `json:"description,omitempty"`
		TokenSecret *oauth.Token   `json:"token,omitempty"`
		Permissions oauth.ScopeList    `json:"permissions,omitempty"`
		Metadata    types.Metadata `json:"metadata,omitempty"`
	}

	// AudienceUpdateInput is the audience update request
	AudienceUpdateInput struct {
		AudienceID  types.ID       `json:"audience_id" structs:"-"`
		Name        *string        `json:"name" structs:"name,omitempty"`
		Description *string        `json:"description,omitempty" structs:"description,omitempty"`
		TokenSecret *oauth.Token   `json:"token,omitempty" structs:"token,omitempty"`
		Permissions oauth.ScopeList    `json:"permissions,omitempty" structs:"permissions,omitempty"`
		Metadata    types.Metadata `json:"metadata,omitempty" structs:"metadata,omitempty"`
	}

	// AudienceGetInput is used to get an audience for the id
	AudienceGetInput struct {
		AudienceID *types.ID `json:"audience_id,omitempty"`
		Name       *string   `json:"name,omitempty"`
	}

	// AudienceListInput is the audience list request
	AudienceListInput struct {
		Limit  *uint64 `json:"limit,omitempty"`
		Offset *uint64 `json:"offset,omitempty"`
	}

	// AudienceDeleteInput is the audience delete request input
	AudienceDeleteInput struct {
		AudienceID types.ID `json:"audience_id"`
	}
)

// ValidateWithContext handles validation of the AudienceCreateInput struct
func (a AudienceCreateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.Name, validation.Required, validation.Length(3, 64)),
		validation.Field(&a.TokenSecret, validation.Required),
		validation.Field(&a.Permissions, validation.Required),
	)
}

// ValidateWithContext handles validation of the AudienceUpdateInput struct
func (a AudienceUpdateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.AudienceID, validation.Required),
		validation.Field(&a.Name, validation.NilOrNotEmpty, validation.Length(3, 64)),
		validation.Field(&a.TokenSecret, validation.NilOrNotEmpty),
		validation.Field(&a.Permissions, validation.NilOrNotEmpty),
	)
}

// ValidateWithContext handles validation of the AudienceGetInput struct
func (a AudienceGetInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.AudienceID, validation.When(a.Name == nil, validation.Required).Else(validation.Nil)),
		validation.Field(&a.Name, validation.When(a.AudienceID == nil, validation.Required).Else(validation.Nil)),
	)
}

// ValidateWithContext handles validation of the AudienceListInput struct
func (a AudienceListInput) ValidateWithContext(context.Context) error {
	return nil
}

// ValidateWithContext handles validation of the ApplicationDeleteInput
func (a AudienceDeleteInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&a,
		validation.Field(&a.AudienceID, validation.Required),
	)
}

// AudienceCreate create a new permission object
func (h *Hiro) AudienceCreate(ctx context.Context, params AudienceCreateInput) (*Audience, error) {
	var aud Audience

	log := api.Log(ctx).WithField("operation", "AudienceCreate").WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new audience")

		stmt, args, err := sq.Insert("hiro.audiences").
			Columns(
				"name",
				"description",
				"token",
				"permissions",
				"metadata").
			Values(
				slug.Make(params.Name),
				null.String(params.Description),
				params.TokenSecret,
				params.Permissions,
				null.JSON(params.Metadata),
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(`RETURNING *`).
			ToSql()
		if err != nil {
			log.Error(err.Error())

			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &aud, stmt, args...); err != nil {
			log.Error(err.Error())

			return parseSQLError(err)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	log.Debugf("audience %s created", aud.ID)

	return &aud, nil
}

// AudienceUpdate updates an application by id, including child objects
func (h *Hiro) AudienceUpdate(ctx context.Context, params AudienceUpdateInput) (*Audience, error) {
	var aud Audience

	log := api.Log(ctx).WithField("operation", "AudienceUpdate").WithField("id", params.AudienceID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("updating audience")

		q := sq.Update("hiro.audiences").
			PlaceholderFormat(sq.Dollar)

		updates := structs.Map(params)

		if _, ok := updates["token"]; ok {
			updates["token"] = sq.Expr(fmt.Sprintf("COALESCE(token, '{}') || %s", sq.Placeholders(1)), params.TokenSecret)
		}

		if _, ok := updates["metadata"]; ok {
			updates["metadata"] = sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata)
		}

		if len(updates) > 0 {
			stmt, args, err := q.Where(sq.Eq{"id": params.AudienceID}).
				SetMap(updates).
				Suffix("RETURNING *").
				ToSql()
			if err != nil {
				log.Error(err.Error())

				return fmt.Errorf("%w: failed to build query statement", err)
			}

			if err := tx.GetContext(ctx, &aud, stmt, args...); err != nil {
				log.Error(err.Error())

				return parseSQLError(err)
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	log.Debugf("audience %s updated", aud.Name)

	return &aud, nil
}

// AudienceGet gets an audience by id and optionally preloads child objects
func (h *Hiro) AudienceGet(ctx context.Context, params AudienceGetInput) (*Audience, error) {
	var suffix string

	log := api.Log(ctx).WithField("operation", "AudienceGet").
		WithField("id", params.AudienceID).
		WithField("name", params.Name)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

	if IsTransaction(db) {
		suffix = "FOR UPDATE"
	}

	query := sq.Select("*").
		From("hiro.audiences").
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
		log.Error(err.Error())

		return nil, parseSQLError(err)
	}

	aud := &Audience{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(aud); err != nil {
		log.Error(err.Error())

		return nil, parseSQLError(err)
	}

	return aud, nil
}

// AudienceList returns a listing of audiences
func (h *Hiro) AudienceList(ctx context.Context, params AudienceListInput) ([]*Audience, error) {
	log := api.Log(ctx).WithField("operation", "AudienceList")

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)

	query := sq.Select("*").
		From("hiro.audiences")

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

	auds := make([]*Audience, 0)
	if err := db.SelectContext(ctx, &auds, stmt, args...); err != nil {
		return nil, parseSQLError(err)
	}

	return auds, nil
}

// AudienceDelete deletes an audience by id
func (h *Hiro) AudienceDelete(ctx context.Context, params AudienceDeleteInput) error {
	log := api.Log(ctx).WithField("operation", "AudienceDelete").WithField("article", params.AudienceID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := h.DB(ctx)
	if _, err := sq.Delete("hiro.audiences").
		Where(
			sq.Eq{"id": params.AudienceID},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to delete application %s: %s", params.AudienceID, err)
		return parseSQLError(err)
	}

	return nil
}
