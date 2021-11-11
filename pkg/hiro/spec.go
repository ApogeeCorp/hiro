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
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/go-openapi/loads"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type (
	// SpecController is the permission API interface
	SpecController interface {
		SpecCreate(ctx context.Context, params SpecCreateParams) (*Spec, error)
	}

	// Spec is an api permission object
	Spec struct {
		ID          ID           `json:"id" db:"id"`
		CreatedAt   time.Time    `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time   `json:"updated_at,omitempty" db:"updated_at"`
		ApiID       ID           `json:"api_id" db:"api_id"`
		Version     string       `json:"version" db:"version"`
		Spec        []byte       `json:"spec" db:"spec"`
		SpecType    SpecType     `json:"spec_type" db:"spec_type"`
		SpecFormat  SpecFormat   `json:"spec_format" db:"spec_format"`
		Permissions []Permission `json:"permissions,omitempty" db:"-"`
	}

	SpecCreateParams struct {
		Params
		ApiID       ID                       `json:"api_id"`
		Version     *string                  `json:"version,omitempty"`
		Spec        []byte                   `json:"spec"`
		SpecType    SpecType                 `json:"spec_type"`
		SpecFormat  SpecFormat               `json:"spec_format"`
		Permissions []PermissionCreateParams `json:"permissions,omitempty"`
	}

	// SpecType defines a specification type
	SpecType string

	// SpecFormat defines a format for the type
	SpecFormat string
)

const (
	SpecTypeOpenAPI SpecType = "openapi"
	SpecTypeRPC     SpecType = "rpc"

	SpecFormatSwagger    SpecFormat = "swagger-2.0"
	SpecFormatGrpcProto2 SpecFormat = "grpc-proto2"
)

// ValidateWithContext validates the SpecCreateInput type
func (i SpecCreateParams) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStruct(&i,
		validation.Field(&i.ApiID, validation.Required),
		validation.Field(&i.Spec, validation.Required),
		validation.Field(&i.SpecType, validation.Required),
		validation.Field(&i.SpecFormat, validation.Required),
		validation.Field(&i.Version, is.Semver),
	)
}

func (h *Hiro) SpecCreate(ctx context.Context, params SpecCreateParams) (*Spec, error) {
	var spec Spec

	log := Log(ctx).WithField("operation", "SpecCreate").WithField("api_id", params.ApiID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	switch params.SpecType {
	case SpecTypeOpenAPI:
		switch params.SpecFormat {
		case SpecFormatSwagger:
			// intialize the hiro api
			doc, err := loads.Analyzed(params.Spec, "")
			if err != nil {
				return nil, fmt.Errorf("failed to load swagger document: %w", err)
			}
			info := doc.Spec().Info

			params.Version = ptr.String(info.Version)

			params.Permissions = make([]PermissionCreateParams, 0)

			for def, sch := range doc.Spec().SecurityDefinitions {
				if sch.Type != "oauth2" {
					continue
				}

				for scope, desc := range sch.Scopes {
					desc := desc
					params.Permissions = append(params.Permissions, PermissionCreateParams{
						Definition:  def,
						Scope:       scope,
						Description: &desc,
					})
				}
			}
		}
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		log.Debugf("creating new spec")

		query := sq.Insert("hiro.api_specs").
			Columns(
				"api_id",
				"spec",
				"spec_type",
				"spec_format",
				"version",
			).
			Values(
				params.ApiID,
				params.Spec,
				params.SpecType,
				params.SpecFormat,
				params.Version,
			).
			PlaceholderFormat(sq.Dollar)

		if params.UpdateOnConflict {
			query = query.Suffix(`ON CONFLICT ON CONSTRAINT spec_format DO UPDATE SET version=$6 RETURNING *`, params.Version)
		} else {
			query = query.Suffix("RETURNING *")
		}

		stmt, args, err := query.ToSql()
		if err != nil {
			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &spec, stmt, args...); err != nil {
			return ParseSQLError(err)
		}

		// create any necessary permissions
		for _, p := range params.Permissions {
			p.Params = params.Params
			p.ApiID = params.ApiID
			p.SpecID = &spec.ID

			if _, err := h.PermissionCreate(ctx, p); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		log.Error(err.Error())

		return nil, err
	}

	log.Debugf("spec %s created", spec.ID)

	return &spec, nil
}

// Expand implements the expandable interface
func (s *Spec) Expand(ctx context.Context, e ...string) error {
	h := FromContext(ctx)
	if h == nil {
		return ErrContextNotFound
	}

	db := h.DB(ctx)

	expand := common.StringSlice(e)

	if expand.ContainsAny("permissions", "*") {
		s.Permissions = make([]Permission, 0)

		stmt, args, err := sq.Select("*").
			From("hiro.api_permissions").
			Where(sq.Eq{
				"api_id":  s.ApiID,
				"spec_id": s.ID,
			}).
			PlaceholderFormat(sq.Dollar).
			ToSql()
		if err != nil {
			return fmt.Errorf("failed to expand permissions: %w", err)
		}

		if err := db.SelectContext(ctx, &s.Permissions, stmt, args...); err != nil {
			return ParseSQLError(err)
		}
	}

	return nil
}
