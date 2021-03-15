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

package common

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/ModelRocket/hiro/pkg/generic"
	"github.com/kr/pretty"
	"github.com/spf13/cast"
)

type (
	// Map is the standard wrapper around a map[string]interface{}
	Map map[string]interface{}
)

var (
	// PathSeparator is the character used to separate the elements
	// of the keypath.
	//
	// For example, `location.address.city`
	PathSeparator = "."

	// SignatureSeparator is the character that is used to
	// separate the Base64 string from the security signature.
	SignatureSeparator = "_"
)

// Validate validates this map
func (m Map) Validate() error {
	return nil
}

// Value returns Map as a value that can be stored as json in the database
func (m Map) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan reads a json value from the database into a Map
func (m Map) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(b, &m)
}

// IsSet returns true if the parameter is set
func (m Map) IsSet(key interface{}) bool {
	_, ok := m[cast.ToString(key)]
	return ok
}

// Set sets a value in the map
func (m Map) Set(key, value interface{}) {
	keypath := cast.ToString(key)

	segs := strings.Split(keypath, PathSeparator)

	if len(segs) == 1 {
		m[segs[0]] = value
		return
	}

	switch val := m[segs[0]].(type) {
	case Map:
		val.Set(strings.Join(segs[1:], "."), value)

	case *Map:
		val.Set(strings.Join(segs[1:], "."), value)

	case map[string]interface{}:
		Map(val).Set(strings.Join(segs[1:], "."), value)

	default:
		refVal := reflect.ValueOf(val)
		switch refVal.Kind() {
		case reflect.Invalid:
			if index, err := cast.ToIntE(segs[1]); err == nil {
				tmp := make([]*Map, index+1)
				tmp[index] = &Map{segs[2]: value}
				m[segs[0]] = tmp
			} else if segs[1] == "$" {
				tmp := make([]Map, 0)

				switch subVal := value.(type) {
				case []Map:
					for _, v := range subVal {
						tmp = append(tmp, v)
					}
				case []*Map:
					for _, v := range subVal {
						tmp = append(tmp, *v)
					}
				case []map[string]interface{}:
					for _, v := range subVal {
						smap := Map(v)
						tmp = append(tmp, smap)
					}
				}
				m[segs[0]] = tmp
			} else {
				m[segs[0]] = make(Map)
				Map(m[segs[0]].(Map)).Set(strings.Join(segs[1:], "."), value)
			}

		case reflect.Slice:
			if tmp, ok := val.([]Map); ok {
				switch subVal := value.(type) {
				case []Map:
					for i, v := range subVal {
						for k, v := range v {
							tmp[i].Set(k, v)
						}
					}
				case []*Map:
					for i, v := range subVal {
						for k, v := range *v {
							tmp[i].Set(k, v)
						}
					}
				case []map[string]interface{}:
					for i, v := range subVal {
						for k, v := range v {
							tmp[i].Set(k, v)
						}
					}
				}
			}

		default:
			pretty.Log("error default")
		}
	}
}

// Get returns the value and if the key is set
func (m Map) Get(key interface{}) generic.Value {
	keypath := cast.ToString(key)

	var segs = strings.Split(keypath, PathSeparator)

	if len(segs) == 1 {
		return generic.MakeValue(m[segs[0]])
	}

	switch val := m[segs[0]].(type) {
	case Map:
		return val.Get(strings.Join(segs[1:], "."))

	case *Map:
		return val.Get(strings.Join(segs[1:], "."))

	case map[string]interface{}:
		return Map(val).Get(strings.Join(segs[1:], "."))

	default:
		refVal := reflect.ValueOf(val)
		if refVal.Kind() == reflect.Slice {
			if segs[1] == "$" {
				if len(segs[2:]) < 1 {
					return generic.MakeValue(nil)
				}

				rval := make([]Map, 0)
				for i := 0; i < refVal.Len(); i++ {
					val := refVal.Index(i).Interface()

					if len(segs[2:]) < 1 {
						rval = append(rval, Map{segs[2]: val})
						continue
					}

					switch vv := val.(type) {
					case Map:
						rval = append(rval, Map{segs[2]: vv.Get(strings.Join(segs[2:], "."))})

					case *Map:
						rval = append(rval, Map{segs[2]: vv.Get(strings.Join(segs[2:], "."))})

					case map[string]interface{}:
						rval = append(rval, Map{segs[2]: Map(vv).Get(strings.Join(segs[2:], "."))})

					default:
						rval = append(rval, Map{segs[2]: vv})
					}
				}
				return generic.MakeValue(rval)
			}

			index := cast.ToInt(segs[1])
			if index < refVal.Len() {
				ival := refVal.Index(index).Interface()

				if len(segs[2:]) < 1 {
					return generic.MakeValue(ival)
				}

				switch vv := ival.(type) {
				case Map:
					return vv.Get(strings.Join(segs[2:], "."))

				case *Map:
					return vv.Get(strings.Join(segs[2:], "."))

				case map[string]interface{}:
					return Map(vv).Get(strings.Join(segs[2:], "."))

				default:
					return generic.MakeValue(vv)
				}
			} else {
				return generic.MakeValue(nil)
			}
		}

		return generic.MakeValue(val)
	}
}

// Sub returns a sub Map for the key
func (m Map) Sub(key interface{}) generic.Map {
	if tmp := m.Get(key); !tmp.IsNil() {
		switch p := tmp.Interface().(type) {
		case map[string]interface{}:
			return Map(p)
		default:
			return generic.MakeMap(p)
		}
	}
	return Map{}
}

// Delete removes a key
func (m Map) Delete(key interface{}) {
	keypath := cast.ToString(key)

	var segs = strings.Split(keypath, PathSeparator)

	if len(segs) == 1 {
		delete(m, segs[0])
		return
	}

	switch val := m[segs[0]].(type) {
	case Map:
		val.Delete(strings.Join(segs[1:], "."))

	case *Map:
		val.Delete(strings.Join(segs[1:], "."))

	case map[string]interface{}:
		Map(val).Delete(strings.Join(segs[1:], "."))

	default:
		refVal := reflect.ValueOf(val)
		if refVal.Kind() == reflect.Slice {
			generic.MakeSlice(val).ToMap().Delete(strings.Join(segs[1:], "."))
		}
	}
}

// DeleteAll removes several keys
func (m Map) DeleteAll(keys ...interface{}) {
	for _, key := range keys {
		delete(m, cast.ToString(key))
	}
}

// Copy does a shallow copy
func (m Map) Copy() generic.Map {
	rval := make(Map)
	for k, v := range m {
		rval[k] = v
	}
	return rval
}

// Without removes the keys, returns a shallow copy
func (m Map) Without(keys ...interface{}) generic.Map {
	if len(keys) == 0 {
		return m
	}
	rval := m.Copy().(Map)
	for _, key := range keys {
		rval.Delete(key)
	}
	return rval
}

// With returns a map with only the specified keys
func (m Map) With(keys ...interface{}) generic.Map {
	if len(keys) == 0 {
		return m
	}

	rval := make(Map)
	for _, key := range keys {
		rval.Set(key, m.Get(key))
	}
	return rval
}

// Map returns the string map
func (m Map) Map() map[string]interface{} {
	return m
}

// ForEach iterates over the map
func (m Map) ForEach(itr func(key, value interface{})) {
	for k, v := range m {
		itr(k, v)
	}
}

// GetValue returns a Value and if the key is set
func (m Map) GetValue(key string) (generic.Value, bool) {
	v, ok := m[key]
	return generic.MakeValue(v), ok
}

// String returns a string value for the param, or the optional default
func (m Map) String(key string, def ...string) string {
	rval := m.Get(key)
	if rval == nil {
		if len(def) > 0 {
			return def[0]
		}
		return ""
	}

	return cast.ToString(rval)
}

// StringPtr returns a string ptr or nil
func (m Map) StringPtr(key string, def ...string) *string {
	rval := m.Get(key)
	if rval == nil {
		if len(def) > 0 {
			return &def[0]
		}
		return nil
	}
	tmp := cast.ToString(rval)
	return &tmp
}

// StringSlice returns a string value for the param, or the optional default
func (m Map) StringSlice(key string) []string {
	rval := m.Get(key)
	if rval == nil {
		return []string{}
	}

	return cast.ToStringSlice(rval)
}

// Bool parses and returns the boolean value of the parameter
func (m Map) Bool(key string, def ...bool) bool {
	rval := m.Get(key)
	if rval == nil {
		if len(def) > 0 {
			return def[0]
		}
		return false
	}

	return cast.ToBool(rval)
}

// Int64 returns the int value or 0 if not set
func (m Map) Int64(key string, def ...int64) int64 {
	rval := m.Get(key)
	if rval.IsNil() {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}

	return rval.Int64()
}

// Int returns the int value or 0 if not set
func (m Map) Int(key string, def ...int) int {
	rval := m.Get(key)
	if rval.IsNil() {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}

	return rval.Int()
}

// Duration returns a duration value
func (m Map) Duration(key string, def ...time.Duration) time.Duration {
	rval := m.Get(key)
	if rval == nil {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}
	return rval.Duration()
}

// Float64 returns the float value or 0 if not set
func (m Map) Float64(key string, def ...float64) float64 {
	rval := m.Get(key)
	if rval == nil {
		if len(def) > 0 {
			return def[0]
		}
		return 0
	}
	return rval.Float64()
}

// Keys returns the keys from the map
func (m Map) Keys() interface{} {
	keys := make([]string, 0)
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Values returns the keys from the map
func (m Map) Values() interface{} {
	vals := make([]interface{}, 0)
	for _, v := range m {
		vals = append(vals, v)
	}
	return vals
}
