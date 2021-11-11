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
	"encoding/json"
	"fmt"
	"sync"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/generic"
	"github.com/ModelRocket/hiro/pkg/safe"
	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/patrickmn/go-cache"
)

type (
	// OptionController provides instance configuration
	OptionController interface {
		// OptionUpdate stores a named option in the backend data store, the value should be created if it does not exist
		OptionUpdate(ctx context.Context, params *OptionUpdateParams) (*Option, error)

		// OptionGet returns a named option from the backend, an error should be returned if the option does not exist
		OptionGet(ctx context.Context, params *OptionGetParams) (*Option, error)

		// OptionList returns a list of options
		OptionList(ctx context.Context, params *OptionListParams) (Options, error)

		// OptionRemove removes the named option from the backend, and error should not be returned if the option does not exist
		OptionRemove(ctx context.Context, params *OptionRemoveParams) error
	}

	// OptionUpdateParams is the option update input
	OptionUpdateParams struct {
		Params
		DomainID   ID              `json:"domain_id"`
		InstanceID *ID             `json:"instance_id,omitempty"`
		Key        string          `json:"key"`
		Value      json.RawMessage `json:"value"`
		TTL        *int            `json:"ttl,omitempty"`
	}

	// OptionGetParams is the option get input
	OptionGetParams struct {
		Params
		DomainID   ID     `json:"domain_id"`
		InstanceID *ID    `json:"instance_id,omitempty"`
		Key        string `json:"key"`
	}

	// OptionListParams is the option list input
	OptionListParams struct {
		Params
		DomainID   ID  `json:"domain_id"`
		InstanceID *ID `json:"instance_id,omitempty"`
	}

	// OptionRemoveParams is the option get input
	OptionRemoveParams struct {
		Params
		DomainID   ID     `json:"domain_id"`
		InstanceID *ID    `json:"instance_id,omitempty"`
		Key        string `json:"key"`
	}

	// OptionUpdateHandler is called when options are updated
	OptionUpdateHandler func(context.Context, *Option) error

	// Option defines domain based option
	Option struct {
		ID         int             `json:"id" db:"id"`
		DomainID   ID              `json:"domain_id" db:"domain_id"`
		InstanceID *ID             `json:"instance_id,omitempty" db:"instance_id"`
		Key        string          `json:"key" db:"key"`
		RawValue   json.RawMessage `json:"value" db:"value"`
		TTL        int             `json:"ttl" db:"ttl"`
	}

	// Options is a list of options
	Options []Option
)

var (
	optionUpdateHandlers = make(map[string][]OptionUpdateHandler)
	optionUpdateLock     sync.Mutex

	optionCache = cache.New(5*time.Minute, 10*time.Minute)
)

// Validate validates OptionUpdateInput
func (o OptionUpdateParams) Validate() error {
	return validation.Errors{
		"domain_id":   validation.Validate(&o.DomainID, validation.Required),
		"instance_id": validation.Validate(&o.InstanceID, validation.NilOrNotEmpty),
		"key":         validation.Validate(&o.Key, validation.Required),
		"value":       validation.Validate(&o.Value, validation.Required),
		"ttl":         validation.Validate(&o.TTL, validation.Min(60000)),
	}.Filter()
}

// Validate validates OptionGetInput
func (o OptionGetParams) Validate() error {
	return validation.Errors{
		"domain_id":   validation.Validate(&o.DomainID, validation.Required),
		"instance_id": validation.Validate(&o.InstanceID, validation.NilOrNotEmpty),
		"key":         validation.Validate(&o.Key, validation.Required),
	}.Filter()
}

// Validate validates OptionGetInput
func (o OptionListParams) Validate() error {
	return validation.Errors{
		"domain_id":   validation.Validate(&o.DomainID, validation.Required),
		"instance_id": validation.Validate(&o.InstanceID, validation.NilOrNotEmpty),
	}.Filter()
}

// Validate validates OptionRemoveInput
func (o OptionRemoveParams) Validate() error {
	return validation.Errors{
		"domain_id":   validation.Validate(&o.DomainID, validation.Required),
		"instance_id": validation.Validate(&o.InstanceID, validation.NilOrNotEmpty),
		"key":         validation.Validate(&o.Key, validation.Required),
	}.Filter()
}

// OptionUpdate stores a named option in the backend data store
func (h *Hiro) OptionUpdate(ctx context.Context, params OptionUpdateParams) (*Option, error) {
	var op Option

	log := api.Log(ctx).WithField("operation", "OptionUpdate").WithField("option", params.Key)

	if err := params.Validate(); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	log.Debugf("updating option %s", params.Key)

	query := sq.Insert("hiro.options").
		Columns(
			"domain_id",
			"instance_id",
			"key",
			"value",
		).
		Values(
			params.DomainID,
			params.InstanceID,
			params.Key,
			params.Value,
		).
		PlaceholderFormat(sq.Dollar)

	if params.TTL != nil {
		query = query.Columns("ttl").Values(params.TTL)
	}

	if len(params.Metadata) > 0 {
		query = query.
			Columns("metadata").
			Values(sq.Expr(fmt.Sprintf("COALESCE(metadata, '{}') || %s", sq.Placeholders(1)), params.Metadata))
	}

	if params.UpdateOnConflict {
		query = query.SuffixExpr(sq.Expr(
			`ON CONFLICT ON CONSTRAINT option_domain_key DO UPDATE SET value=$3, ttl=COALESCE(?, ttl) RETURNING *`,
			params.TTL,
		))
	} else {
		query = query.Suffix(`RETURNING *`)
	}

	stmt, args, err := query.ToSql()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to build query statement", err)
	}

	if err := h.Transact(ctx, func(ctx context.Context, tx DB) error {
		if err := tx.GetContext(ctx, &op, stmt, args...); err != nil {
			return ParseSQLError(err)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	go func(op *Option) {
		optionUpdateLock.Lock()
		defer func() {
			if !params.NoCache {
				optionCache.Delete(op.CacheKey())
			}
			optionUpdateLock.Unlock()
		}()

		if handlers, ok := optionUpdateHandlers[params.Key]; ok {
			for _, h := range handlers {
				if err := h(ctx, op); err != nil {
					log.Errorf("failed to process update handler for %s: %s", params.Key, err)
				}
			}
		}
	}(&op)

	return &op, nil
}

// OptionGet returns a named option from the backend
func (h *Hiro) OptionGet(ctx context.Context, params OptionGetParams) (*Option, error) {
	if !params.NoCache {
		if v, ok := optionCache.Get(params.CacheKey()); ok {
			return v.(*Option), nil
		}
	}

	var op Option

	stmt, args, err := sq.
		Select("*").
		From("hiro.options").
		Where(sq.Eq{
			"domain_id":   params.DomainID,
			"instance_id": params.InstanceID,
			"key":         params.Key,
		}).ToSql()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to build query statement", err)
	}

	db := h.DB(ctx)

	if err := db.GetContext(ctx, &op, stmt, args...); err != nil {
		return nil, ParseSQLError(err)
	}

	if !params.NoCache {
		optionCache.Set(params.Key, &op, time.Millisecond*time.Duration(op.TTL))
	}

	return &op, nil
}

// OptionGet returns a named option from the backend
func (h *Hiro) OptionList(ctx context.Context, params OptionListParams) (Options, error) {

	ops := make(Options, 0)

	stmt, args, err := sq.
		Select("*").
		From("hiro.options").
		Where(sq.Eq{
			"domain_id":   params.DomainID,
			"instance_id": params.InstanceID,
		}).ToSql()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to build query statement", err)
	}

	db := h.DB(ctx)

	if err := db.SelectContext(ctx, &ops, stmt, args...); err != nil {
		return nil, ParseSQLError(err)
	}

	return ops, nil
}

// OptionRemove removes the named option from the backend
func (h *Hiro) OptionRemove(ctx context.Context, params OptionRemoveParams) error {
	_, err := h.db.ExecContext(ctx, `DELETE FROM options WHERE key=$1`, params.Key)

	optionUpdateLock.Lock()
	defer optionUpdateLock.Unlock()

	optionCache.Delete(params.Key)

	return err
}

// RegisterOptionUpdateHandler registers an update handler for options
func RegisterOptionUpdateHandler(key string, handler OptionUpdateHandler) {
	optionUpdateLock.Lock()

	defer optionUpdateLock.Unlock()

	if _, ok := optionUpdateHandlers[key]; !ok {
		optionUpdateHandlers[key] = make([]OptionUpdateHandler, 0)
	}

	optionUpdateHandlers[key] = append(optionUpdateHandlers[key], handler)
}

func (o *Option) Value() generic.Value {
	return generic.MakeValue(o.Value())
}

func (o *Option) CacheKey() string {
	return fmt.Sprintf("%s:%s:%s", o.DomainID, safe.String(o.InstanceID, "-"), o.Key)
}

func (o Options) Get(key string, def ...interface{}) generic.Value {
	for _, v := range o {
		if v.Key == key {
			return v.Value()
		}
	}

	if len(def) == 0 {
		return generic.MakeValue(0)
	}

	return generic.MakeValue(def[0])
}

func (o OptionGetParams) CacheKey() string {
	return fmt.Sprintf("%s:%s:%s", o.DomainID, safe.String(o.InstanceID, "-"), o.Key)
}
