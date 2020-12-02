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

package types

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

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
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
	optionRegistry = make(map[string]reflect.Type)
	optionRegLock  sync.Mutex
)

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
