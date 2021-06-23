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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/common"
	"github.com/ModelRocket/hiro/pkg/null"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/fatih/structs"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// AssetController is the asset API interface
	AssetController interface {
		AssetCreate(ctx context.Context, params AssetCreateInput) (*Asset, error)
		AssetGet(ctc context.Context, params AssetGetInput) (*Asset, error)
		AssetList(ctx context.Context, params AssetListInput) ([]*Asset, error)
		AssetUpdate(ctx context.Context, params AssetUpdateInput) (*Asset, error)
		AssetDelete(ctx context.Context, params AssetDeleteInput) error
	}

	// Asset objects are application assets that are stored in the asset volume
	Asset struct {
		ID          ID          `json:"id" db:"id"`
		InstanceID  ID          `json:"instance_id" db:"instance_id"`
		OwnerID     *ID         `json:"owner_id,omitempty" db:"owner_id"`
		Title       string      `json:"title" db:"title"`
		Description *string     `json:"description,omitempty" db:"description"`
		Filename    string      `json:"filename" db:"filename"`
		MimeType    string      `json:"mime_type" db:"mime_type"`
		Size        int64       `json:"size" db:"size"`
		Public      bool        `json:"public" db:"public"`
		CreatedAt   time.Time   `json:"created_at" db:"created_at"`
		UpdatedAt   *time.Time  `json:"updated_at,omitempty" db:"updated_at"`
		Metadata    common.Map  `json:"metadata,omitempty" db:"metadata"`
		SHA256      *string     `json:"sha256,omitempty" db:"sha256"`
		Payload     AssetReader `json:"-" db:"-"`
	}

	// AssetCreateInput is the input to AssetCreate
	AssetCreateInput struct {
		InstanceID  ID         `json:"instance_id"`
		OwnerID     *ID        `json:"owner_id,omitempty"`
		Title       string     `json:"title"`
		Description *string    `json:"description,omitempty"`
		Filename    string     `json:"filename"`
		Public      bool       `json:"public"`
		Metadata    common.Map `json:"metadata,omitempty"`
		Payload     io.Reader  `json:"-"`
	}

	// AssetUpdateInput is the input to AssetUpdate
	AssetUpdateInput struct {
		InstanceID  ID         `json:"instance_id" structs:"instance_id"`
		AssetID     ID         `json:"asset_id" structs:"asset_id"`
		Title       *string    `json:"title" structs:"title,omitempty"`
		Description *string    `json:"description,omitempty" structs:"description,omitempty"`
		Filename    *string    `json:"filename" structs:"filename,omitempty"`
		Public      *bool      `json:"public" structs:"public,omitempty"`
		Metadata    common.Map `json:"metadata,omitempty" structs:"metadata,omitempty"`
		Payload     io.Reader  `json:"-" structs:"-"`
	}

	// AssetGetInput is the input to AssetGet
	AssetGetInput struct {
		InstanceID  ID      `json:"instance_id"`
		AssetID     *ID     `json:"asset_id"`
		Filename    *string `json:"filename"`
		WithPayload bool    `json:"-"`
	}

	// AssetListInput is the input to AssetList
	AssetListInput struct {
		InstanceID ID      `json:"instance_id"`
		Offset     *uint64 `json:"offset,omitempty"`
		Limit      *uint64 `json:"limit,omitempty"`
		Count      *uint64 `json:"count,omitempty"`
		MimeType   *string `json:"mime_type,omitempty"`
	}

	// AssetDeleteInput is the input to AssetDelete
	AssetDeleteInput struct {
		InstanceID ID `json:"instance_id"`
		AssetID    ID `json:"asset_id"`
	}

	// AssetReader is an interface for asset io
	AssetReader interface {
		io.ReadSeeker
		io.Closer
	}
)

// ValidateWithContext handles the validation for the AssetCreateInput
func (a *AssetCreateInput) ValidateWithContext(ctx context.Context) error {
	// handle create from api request
	if r, _ := api.Request(ctx); r != nil {
		if r.MultipartForm == nil || r.MultipartForm.File["file"] == nil {
			return api.ErrBadRequest.WithMessage("missing asset payload")
		}

		fh := r.MultipartForm.File["file"][0]

		file, err := fh.Open()
		if err != nil {
			return api.ErrBadRequest.WithError(err)
		}
		a.Payload = file

		_, parts, err := mime.ParseMediaType(fh.Header.Get("Content-Disposition"))
		if err != nil {
			return api.ErrBadRequest.WithError(err)
		}
		a.Filename = parts["filename"]
	}

	if a.Title == "" {
		a.Title = a.Filename
	}

	return validation.ValidateStructWithContext(ctx, a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.Filename, validation.Required),
		validation.Field(&a.Title, validation.Required),
	)
}

// ValidateWithContext handles the validation for the AssetUpdateInput
func (a *AssetUpdateInput) ValidateWithContext(ctx context.Context) error {
	// handle create from api request
	if r, _ := api.Request(ctx); r != nil {
		if r.MultipartForm != nil && r.MultipartForm.File["file"] != nil {

			fh := r.MultipartForm.File["file"][0]

			file, err := fh.Open()
			if err != nil {
				return api.ErrBadRequest.WithError(err)
			}
			a.Payload = file

			_, parts, err := mime.ParseMediaType(fh.Header.Get("Content-Disposition"))
			if err != nil {
				return api.ErrBadRequest.WithError(err)
			}
			a.Filename = ptr.String(parts["filename"])
		}
	}

	return validation.ValidateStructWithContext(ctx, a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.AssetID, validation.Required),
	)
}

// Validate handles validation for AssetGetInput
func (a AssetGetInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, &a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.AssetID, validation.When(a.Filename == nil, validation.Required)),
		validation.Field(&a.Filename, validation.When(a.AssetID == nil, validation.Required)),
	)
}

// Validate handles validation for AssetGetInput
func (a AssetListInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, &a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.Limit, validation.NilOrNotEmpty),
	)
}

// Validate handles validation for AssetGetInput
func (a AssetDeleteInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, &a,
		validation.Field(&a.InstanceID, validation.Required),
		validation.Field(&a.AssetID, validation.Required),
	)
}

// AssetCreate creates a new asset for the instance
func (b *Hiro) AssetCreate(ctx context.Context, params AssetCreateInput) (*Asset, error) {
	if b.assetVolume == "" {
		return nil, api.ErrNotImplemented.WithMessage("asset volume not configured")
	}

	var asset Asset

	log := Log(ctx).WithField("operation", "AssetCreate").
		WithField("instance", params.InstanceID).
		WithField("filename", params.Filename)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		stmt, args, err := sq.Insert("hiro.assets").
			Columns(
				"instance_id",
				"owner_id",
				"title",
				"filename",
				"description",
				"public",
				"metadata").
			Values(
				params.InstanceID,
				params.OwnerID,
				params.Title,
				params.Filename,
				null.String(params.Description),
				params.Public,
				null.JSON(params.Metadata),
			).
			PlaceholderFormat(sq.Dollar).
			Suffix(`RETURNING *`).
			ToSql()
		if err != nil {
			return fmt.Errorf("%w: failed to build query statement", err)
		}

		if err := tx.GetContext(ctx, &asset, stmt, args...); err != nil {
			return ParseSQLError(err)
		}

		if params.Payload != nil {
			if err := b.assetWrite(ctx, &asset, params.Payload); err != nil {
				return err
			}

			stmt, args, err = sq.Update("hiro.assets").
				Where(sq.Eq{"id": asset.ID}).
				Set("size", asset.Size).
				Set("mime_type", asset.MimeType).
				Set("sha256", asset.SHA256).
				PlaceholderFormat(sq.Dollar).
				Suffix(`RETURNING *`).
				ToSql()
			if err != nil {
				return fmt.Errorf("%w: failed to build query statement", err)
			}

			if err := tx.GetContext(ctx, &asset, stmt, args...); err != nil {
				return ParseSQLError(err)
			}
		}

		return nil
	}); err != nil {
		log.Error(err.Error())

		return nil, err
	}

	log.Debugf("asset %s created", asset.ID)

	return &asset, nil
}

// AssetGet returns the asset in the instance
func (b *Hiro) AssetGet(ctx context.Context, params AssetGetInput) (*Asset, error) {
	var suffix string

	if b.assetVolume == "" {
		return nil, api.ErrNotImplemented.WithMessage("asset volume not configured")
	}

	log := Log(ctx).WithField("operation", "AssetGet").
		WithField("instance", params.InstanceID).
		WithField("id", params.AssetID).
		WithField("filename", params.Filename)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)

	if IsTransaction(db) {
		suffix = "FOR UPDATE"
	}

	query := sq.Select("*").
		From("hiro.assets").
		PlaceholderFormat(sq.Dollar).
		Where(sq.Eq{"instance_id": params.InstanceID})

	if params.AssetID.Valid() {
		query = query.Where(sq.Eq{"id": params.AssetID})
	} else if params.Filename != nil {
		query = query.Where(sq.Or{
			sq.Eq{"filename": *params.Filename},
		})
	} else {
		return nil, fmt.Errorf("%w: asset id or filename required", ErrInputValidation)
	}

	stmt, args, err := query.
		Suffix(suffix).
		ToSql()
	if err != nil {
		log.Error(err.Error())

		return nil, ParseSQLError(err)
	}

	asset := Asset{}

	row := db.QueryRowxContext(ctx, stmt, args...)
	if err := row.StructScan(&asset); err != nil {
		log.Error(err.Error())

		return nil, ParseSQLError(err)
	}

	if params.WithPayload {
		p := filepath.Join(b.assetVolume, asset.InstanceID.String(), asset.ID.String())

		fd, err := os.Open(p)
		if err != nil {
			return nil, err
		}

		asset.Payload = fd
	}

	return &asset, nil
}

// AssetList lists the assets in the instance
func (b *Hiro) AssetList(ctx context.Context, params AssetListInput) ([]*Asset, error) {
	if b.assetVolume == "" {
		return nil, api.ErrNotImplemented.WithMessage("asset volume not configured")
	}

	log := Log(ctx).WithField("operation", "AssetList")

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
		From("hiro.assets")

	if safe.Uint64(params.Limit) > 0 {
		query = query.Limit(*params.Limit)
	}

	if safe.Uint64(params.Offset) > 0 {
		query = query.Offset(*params.Offset)
	}

	if params.MimeType != nil {
		query = query.Where(sq.Eq{"mime_type": params.MimeType})
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

	assets := make([]*Asset, 0)
	if err := db.SelectContext(ctx, &assets, stmt, args...); err != nil {
		return nil, ParseSQLError(err)
	}

	return assets, nil
}

// AssetUpdate updates an asset
func (b *Hiro) AssetUpdate(ctx context.Context, params AssetUpdateInput) (*Asset, error) {
	if b.assetVolume == "" {
		return nil, api.ErrNotImplemented.WithMessage("asset volume not configured")
	}

	log := Log(ctx).WithField("operation", "AssetUpdate").WithField("id", params.AssetID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())

		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	var asset *Asset

	if err := b.Transact(ctx, func(ctx context.Context, tx DB) error {
		var err error

		log.Debugf("updating asset")

		q := sq.Update("hiro.assets").
			PlaceholderFormat(sq.Dollar)

		updates := structs.Map(params)

		if params.Metadata != nil {
			updates["metadata"] = sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata)
		}

		asset, err = b.AssetGet(ctx, AssetGetInput{
			InstanceID: params.InstanceID,
			AssetID:    &params.AssetID,
		})
		if err != nil {
			return err
		}

		if params.Payload != nil {
			if err := b.assetWrite(ctx, asset, params.Payload); err != nil {
				return err
			}

			updates["mime_type"] = asset.MimeType
			updates["size"] = asset.Size
			updates["sha256"] = *asset.SHA256
		}

		if len(updates) > 0 {
			stmt, args, err := q.
				Where(sq.Eq{
					"instance_id": params.InstanceID,
					"id":          params.AssetID,
				}).
				SetMap(updates).
				Suffix("RETURNING *").
				ToSql()
			if err != nil {
				log.Error(err.Error())

				return fmt.Errorf("%w: failed to build query statement", err)
			}

			if err := tx.GetContext(ctx, &asset, stmt, args...); err != nil {
				log.Error(err.Error())

				return ParseSQLError(err)
			}
		} else {
			return ErrInputValidation.WithMessage("nothing to update")
		}

		return nil
	}); err != nil {
		return nil, err
	}

	log.Debugf("asset %s updated", asset.Filename)

	return asset, nil
}

// AssetDelete deletes an asset
func (b *Hiro) AssetDelete(ctx context.Context, params AssetDeleteInput) error {
	if b.assetVolume == "" {
		return api.ErrNotImplemented.WithMessage("asset volume not configured")
	}

	log := Log(ctx).WithField("operation", "AssetDelete").WithField("application", params.AssetID)

	if err := params.ValidateWithContext(ctx); err != nil {
		log.Error(err.Error())
		return fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	db := b.DB(ctx)
	if _, err := sq.Delete("hiro.assets").
		Where(
			sq.Eq{"id": params.AssetID},
			sq.Eq{"instance_id": params.InstanceID},
		).
		PlaceholderFormat(sq.Dollar).
		RunWith(db).
		ExecContext(ctx); err != nil {
		log.Errorf("failed to delete asset %s: %s", params.AssetID, err)
		return ParseSQLError(err)
	}

	return nil
}

func (b *Hiro) assetWrite(ctx context.Context, asset *Asset, payload io.Reader) error {
	log := Log(ctx).WithField("operation", "assetWrite").WithField("asset", asset.ID)

	p := filepath.Join(b.assetVolume, asset.InstanceID.String())

	if err := os.MkdirAll(p, 0755); err != nil && !os.IsExist(err) {
		return err
	}
	name := filepath.Join(p, asset.ID.String())

	log.Debugf("creating asset file %s", name)

	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	sum := sha256.New()
	tee := io.TeeReader(payload, sum)

	len, err := io.Copy(f, tee)
	if err != nil {
		return err
	}
	asset.Size = len
	asset.SHA256 = ptr.String(hex.EncodeToString(sum.Sum(nil)))

	cbuf := make([]byte, 512)

	if _, err := f.Seek(0, 0); err != nil {
		return err
	}

	if _, err := f.Read(cbuf); err != nil {
		return err
	}

	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	asset.MimeType = http.DetectContentType(cbuf)

	return nil
}
