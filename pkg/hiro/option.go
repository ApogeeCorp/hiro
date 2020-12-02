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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/types"
	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/patrickmn/go-cache"
)

type (
	// OptionController provides instance configuration
	OptionController interface {
		// OptionUpdate stores a named option in the backend data store, the value should be created if it does not exist
		OptionUpdate(ctx context.Context, params *OptionUpdateInput) (types.Option, error)

		// OptionGet returns a named option from the backend, an error should be returned if the option does not exist
		OptionGet(ctx context.Context, params *OptionGetInput) (types.Option, error)

		// OptionRemove removes the named option from the backend, and error should not be returned if the option does not exist
		OptionRemove(ctx context.Context, params *OptionRemoveInput) error
	}

	// OptionUpdateInput is the option update input
	OptionUpdateInput struct {
		AudienceID       types.ID   `json:"audience_id"`
		Name             string       `json:"name"`
		Option           types.Option `json:"-"`
		suppressHandlers bool
	}

	// OptionGetInput is the option get input
	OptionGetInput struct {
		Name  string      `json:"name"`
		Value interface{} `json:"-"`
	}

	// OptionRemoveInput is the option get input
	OptionRemoveInput struct {
		Name string `json:"name"`
	}

	// OptionUpdateHandler is called when options are updated
	OptionUpdateHandler func(context.Context, types.Option) error
)

var (
	optionUpdateHandlers = make(map[string][]OptionUpdateHandler)
	optionLock           sync.Mutex

	optionCache = cache.New(5*time.Minute, 10*time.Minute)
)

// Validate validates OptionUpdateInput
func (o OptionUpdateInput) Validate() error {
	return validation.Errors{
		"audience_id": validation.Validate(o.AudienceID, validation.Required),
		"name":        validation.Validate(o.Name, validation.Required),
	}.Filter()
}

// Validate validates OptionGetInput
func (o OptionGetInput) Validate() error {
	return validation.Errors{
		"name": validation.Validate(o.Name, validation.Required),
	}.Filter()
}

// Validate validates OptionRemoveInput
func (o OptionRemoveInput) Validate() error {
	return validation.Errors{
		"name": validation.Validate(o.Name, validation.Required),
	}.Filter()
}

// OptionUpdate stores a named option in the backend data store
func (h *Hiro) OptionUpdate(ctx context.Context, params *OptionUpdateInput) (types.Option, error) {
	log := api.Log(ctx).WithField("operation", "OptionUpdate").WithField("option", params.Name)

	if err := params.Validate(); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	log.Debugf("updating options %s", params.Name)

	if _, err := h.db.ExecContext(
		ctx,
		`INSERT INTO options (audience_id, name, value) 
			VALUES($1, $2, COALESCE(value, '{}') || $3) 
			ON CONFLICT (audience_id,name) SET value=COALESCE(value, '{}') || $3`,
		params.AudienceID,
		params.Name,
		params.Option,
	); err != nil {
		log.Debugf("failed to update option %s: %s", params.Name, err)
		return nil, parseSQLError(err)
	}

	// get the latest version
	op, err := h.OptionGet(ctx, &OptionGetInput{
		Name: params.Name,
	})
	if err != nil {
		return nil, err
	}

	if params.suppressHandlers {
		return op, nil
	}

	go func(op types.Option) {
		optionLock.Lock()
		defer func() {
			optionCache.Delete(params.Name)
			optionLock.Unlock()
		}()

		if handlers, ok := optionUpdateHandlers[params.Name]; ok {
			for _, h := range handlers {
				if err := h(ctx, op); err != nil {
					log.Errorf("failed to process update handler for %s: %s", params.Name, err)
				}
			}
		}
	}(op)

	return op, nil
}

// OptionGet returns a named option from the backend
func (h *Hiro) OptionGet(ctx context.Context, params *OptionGetInput) (types.Option, error) {
	data := make([]byte, 0)

	if v, ok := optionCache.Get(params.Name); ok {
		data = v.([]byte)
	} else {
		query := h.db.QueryRowxContext(ctx, `SELECT value FROM options WHERE name=$1`, params.Name)

		if err := query.Scan(&data); err != nil {
			return nil, parseSQLError(err)
		}

		optionCache.Set(params.Name, data, cache.DefaultExpiration)
	}

	if params.Value != nil {
		if err := json.Unmarshal(data, params.Value); err != nil {
			return nil, err
		}

		if op, ok := params.Value.(types.Option); ok {
			return op, nil
		}

		return nil, fmt.Errorf("%w: value is not a valid option", ErrInputValidation)
	}

	return types.UnmarshalOption(bytes.NewReader(data), params.Name)
}

// OptionRemove removes the named option from the backend
func (h *Hiro) OptionRemove(ctx context.Context, params *OptionRemoveInput) error {
	_, err := h.db.ExecContext(ctx, `DELETE FROM options WHERE name=$1`, params.Name)

	optionLock.Lock()
	defer optionLock.Unlock()

	optionCache.Delete(params.Name)

	return err
}

// RegisterOptionUpdateHandler registers an update handler for options
func RegisterOptionUpdateHandler(name string, handler OptionUpdateHandler) {
	optionLock.Lock()

	defer optionLock.Unlock()

	if _, ok := optionUpdateHandlers[name]; !ok {
		optionUpdateHandlers[name] = make([]OptionUpdateHandler, 0)
	}

	optionUpdateHandlers[name] = append(optionUpdateHandlers[name], handler)
}
