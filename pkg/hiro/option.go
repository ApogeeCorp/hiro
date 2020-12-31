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
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ModelRocket/sparks/pkg/api"
	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/patrickmn/go-cache"
)

type (
	// OptionController provides instance configuration
	OptionController interface {
		// OptionUpdate stores a named option in the backend data store, the value should be created if it does not exist
		OptionUpdate(ctx context.Context, params *OptionUpdateInput) (Option, error)

		// OptionGet returns a named option from the backend, an error should be returned if the option does not exist
		OptionGet(ctx context.Context, params *OptionGetInput) (Option, error)

		// OptionRemove removes the named option from the backend, and error should not be returned if the option does not exist
		OptionRemove(ctx context.Context, params *OptionRemoveInput) error
	}

	// OptionUpdateInput is the option update input
	OptionUpdateInput struct {
		AudienceID       ID     `json:"audience_id"`
		Name             string `json:"name"`
		Option           Option `json:"-"`
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
	OptionUpdateHandler func(context.Context, Option) error

	// Option An instance configuration option
	Option interface {
		Name() string
		SetName(string)
		Audience() string
		SetAudience(string)
	}

	option struct {
		name     string
		audience string
	}
)

var (
	optionUpdateHandlers = make(map[string][]OptionUpdateHandler)
	optionLock           sync.Mutex

	optionRegistry = make(map[string]reflect.Type)
	optionRegLock  sync.Mutex

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
func (b *Backend) OptionUpdate(ctx context.Context, params *OptionUpdateInput) (Option, error) {
	log := api.Log(ctx).WithField("operation", "OptionUpdate").WithField("option", params.Name)

	if err := params.Validate(); err != nil {
		log.Error(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrInputValidation, err)
	}

	log.Debugf("updating options %s", params.Name)

	if _, err := b.db.ExecContext(
		ctx,
		`INSERT INTO options (audience_id, name, value) 
			VALUES($1, $2, COALESCE(value, '{}') || $3) 
			ON CONFLICT (audience_id,name) SET value=COALESCE(value, '{}') || $3`,
		params.AudienceID,
		params.Name,
		params.Option,
	); err != nil {
		log.Debugf("failed to update option %s: %s", params.Name, err)
		return nil, ParseSQLError(err)
	}

	// get the latest version
	op, err := b.OptionGet(ctx, &OptionGetInput{
		Name: params.Name,
	})
	if err != nil {
		return nil, err
	}

	if params.suppressHandlers {
		return op, nil
	}

	go func(op Option) {
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
func (b *Backend) OptionGet(ctx context.Context, params *OptionGetInput) (Option, error) {
	data := make([]byte, 0)

	if v, ok := optionCache.Get(params.Name); ok {
		data = v.([]byte)
	} else {
		query := b.db.QueryRowxContext(ctx, `SELECT value FROM options WHERE name=$1`, params.Name)

		if err := query.Scan(&data); err != nil {
			return nil, ParseSQLError(err)
		}

		optionCache.Set(params.Name, data, cache.DefaultExpiration)
	}

	if params.Value != nil {
		if err := json.Unmarshal(data, params.Value); err != nil {
			return nil, err
		}

		if op, ok := params.Value.(Option); ok {
			return op, nil
		}

		return nil, fmt.Errorf("%w: value is not a valid option", ErrInputValidation)
	}

	return UnmarshalOption(bytes.NewReader(data), params.Name)
}

// OptionRemove removes the named option from the backend
func (b *Backend) OptionRemove(ctx context.Context, params *OptionRemoveInput) error {
	_, err := b.db.ExecContext(ctx, `DELETE FROM options WHERE name=$1`, params.Name)

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

// RegisterOption registers an option type
func RegisterOption(name string, val interface{}) error {
	optionRegLock.Lock()
	defer optionRegLock.Unlock()

	if _, ok := val.(Option); !ok {
		return errors.New("invalid option type")
	}

	typ := reflect.TypeOf(val)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	optionRegistry[strings.ToLower(name)] = typ

	return nil
}

// Name gets the name of this polymorphic type
func (m *option) Name() string {
	if m.name != "" {
		return m.name
	}

	return "Option"
}

// SetName sets the name of this polymorphic type
func (m *option) SetName(val string) {
	m.name = val
}

// Audience returns the audience
func (m *option) Audience() string {
	return m.audience
}

// SetAudience sets the audience
func (m *option) SetAudience(val string) {
	m.audience = val
}

// UnmarshalOptionSlice unmarshals polymorphic slices of Option
func UnmarshalOptionSlice(reader io.Reader) ([]Option, error) {
	var elements []json.RawMessage
	dec := json.NewDecoder(reader)
	dec.UseNumber()
	if err := dec.Decode(&elements); err != nil {
		return nil, err
	}

	var result []Option
	for _, element := range elements {
		obj, err := unmarshalOption(element)
		if err != nil {
			return nil, err
		}
		result = append(result, obj)
	}
	return result, nil
}

// UnmarshalOption unmarshals polymorphic Option
func UnmarshalOption(reader io.Reader, name ...string) (Option, error) {
	// we need to read this twice, so first into a buffer
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return unmarshalOption(data, name...)
}

func unmarshalOption(data []byte, name ...string) (Option, error) {
	buf := bytes.NewBuffer(data)
	buf2 := bytes.NewBuffer(data)

	var optionName string

	if len(name) == 0 {
		// the first time this is read is to fetch the value of the name property.
		var getType struct {
			Name string `json:"name"`
		}
		dec := json.NewDecoder(buf)
		dec.UseNumber()
		if err := dec.Decode(&getType); err != nil {
			return nil, err
		}

		if err := (validation.Errors{
			"name": validation.Validate(getType.Name, validation.Required),
		}).Filter(); err != nil {
			return nil, err
		}

		optionName = getType.Name
	} else {
		optionName = name[0]
	}

	var result Option

	dec := json.NewDecoder(buf2)
	dec.UseNumber()

	t, ok := optionRegistry[strings.ToLower(optionName)]
	if !ok {
		return nil, fmt.Errorf("unregistered name value: %q", optionName)
	}

	result = reflect.New(t).Interface().(Option)

	if err := dec.Decode(result); err != nil {
		return nil, err
	}

	if v, ok := result.(validation.Validatable); ok {
		if err := v.Validate(); err != nil {
			return nil, err
		}
	} else if v, ok := result.(validation.ValidatableWithContext); ok {
		if err := v.ValidateWithContext(context.Background()); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Value returns Option as a value that can be stored as json in the database
func (m option) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a Option
func (m *option) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	return nil
}
