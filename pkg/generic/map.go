/*************************************************************************
 * MIT License
 * Copyright (c) 2021 Model Rocket
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package generic

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"unicode"

	"github.com/spf13/cast"
)

type (
	// Map provides a map wrapper interface for working easily with unknown map types
	Map interface {
		IsSet(key interface{}) bool
		Set(key, value interface{})
		Get(key interface{}) Value
		Sub(key interface{}) Map
		Delete(key interface{})
		DeleteAll(keys ...interface{})
		Copy() Map
		With(keys ...interface{}) Map
		Without(keys ...interface{}) Map
		Values() interface{}
		Keys() interface{}
		Map() map[string]interface{}
		ForEach(func(key, value interface{}))
	}

	reflectMap struct {
		v reflect.Value
	}
)

// MakeMap returns a Mapper from the passed map
func MakeMap(m interface{}) Map {
	v := reflect.ValueOf(m)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Map {
		panic("not a map")
	}

	return &reflectMap{v: v}
}

func (m reflectMap) IsSet(key interface{}) bool {
	return m.v.MapIndex(reflect.ValueOf(key)).IsValid()
}

// Set sets a value in the map
func (m reflectMap) Set(key, value interface{}) {
	m.v.SetMapIndex(reflect.ValueOf(key), reflect.ValueOf(value))
}

// Keys returns the keys from the map
func (m reflectMap) Keys() interface{} {
	keySlice := reflect.SliceOf(m.v.Type().Key())
	keys := reflect.MakeSlice(keySlice, m.v.Len(), m.v.Len())

	for i, key := range m.v.MapKeys() {
		idx := keys.Index(i)
		idx.Set(key)
	}
	return keys.Interface()
}

// Values returns the values from the map
func (m reflectMap) Values() interface{} {
	valSlice := reflect.SliceOf(m.v.Type().Elem())
	values := reflect.MakeSlice(valSlice, m.v.Len(), m.v.Len())

	for i, key := range m.v.MapKeys() {
		val := m.v.MapIndex(key)
		idx := values.Index(i)
		idx.Set(val)
	}
	return values.Interface()
}

// Get returns a value from a map
func (m reflectMap) Get(key interface{}) Value {
	v := m.v.MapIndex(reflect.ValueOf(key))
	if !v.CanInterface() {
		return nil
	}
	return MakeValue(v.Interface())
}

// Sub returns a sub map
func (m reflectMap) Sub(key interface{}) Map {
	v := m.v.MapIndex(reflect.ValueOf(key))
	if !v.CanInterface() {
		return nil
	}
	if v.Kind() != reflect.Map {
		return nil
	}
	return MakeMap(v.Interface())
}

// Delete removes a value from a map
func (m reflectMap) Delete(key interface{}) {
	m.v.SetMapIndex(reflect.ValueOf(key), reflect.Value{})
}

// DeleteAll removes a value from a map
func (m reflectMap) DeleteAll(keys ...interface{}) {
	for _, key := range keys {
		m.v.SetMapIndex(reflect.ValueOf(key), reflect.Value{})
	}
}

// Copy returns a copy of a map
func (m reflectMap) Copy() Map {
	dst := reflect.New(reflect.TypeOf(m.v))

	for _, k := range m.v.MapKeys() {
		ov := m.v.MapIndex(k)
		dst.SetMapIndex(k, ov)
	}
	return &reflectMap{dst}
}

// Cast returns a Caster to convert a value to another type
func (m reflectMap) Cast(key interface{}) Value {
	v := m.v.MapIndex(reflect.ValueOf(key))
	if !v.CanInterface() {
		return MakeValue(nil)
	}
	return MakeValue(v.Interface())
}

// Without returns a copy of the map without the specified keys
func (m reflectMap) Without(keys ...interface{}) Map {
	dst := m.Copy()

	for _, key := range keys {
		dst.Delete(key)
	}

	return dst
}

// With returns a copy of the map with the specified keys
func (m reflectMap) With(keys ...interface{}) Map {
	dst := reflect.New(reflect.TypeOf(m.v))

	for _, key := range keys {
		dst.SetMapIndex(reflect.ValueOf(key), reflect.ValueOf(m.Get(key)))
	}

	return MakeMap(dst.Interface())
}

func (m reflectMap) Map() map[string]interface{} {
	rval := make(map[string]interface{})

	m.ForEach(func(k, v interface{}) {
		rval[cast.ToString(k)] = v
	})

	return rval
}

func (m reflectMap) ForEach(itr func(key, value interface{})) {
	for _, key := range m.v.MapKeys() {
		itr(key, m.Get(key))
	}
}

// ParseString parses a mapping string and returns a params object
// Example string: foo=bar aparam="value"
func ParseString(s string) Map {
	m := make(map[string]interface{})

	lastQuote := rune(0)
	f := func(c rune) bool {
		switch {
		case c == lastQuote:
			lastQuote = rune(0)
			return false
		case lastQuote != rune(0):
			return false
		case unicode.In(c, unicode.Quotation_Mark):
			lastQuote = c
			return false
		default:
			return unicode.IsSpace(c)

		}
	}

	// splitting string by space but considering quoted section
	items := strings.FieldsFunc(s, f)

	for _, item := range items {
		x := strings.SplitN(item, "=", 2)
		update := func(val interface{}) {
			if m[x[0]] != nil {
				if arr, ok := m[x[0]].([]interface{}); ok {
					m[x[0]] = append(arr, val)
				} else {
					tmp := m[x[0]]
					m[x[0]] = []interface{}{tmp, val}
				}
			} else {
				m[x[0]] = val
			}
		}

		if len(x) > 1 {
			if v, err := strconv.Unquote(x[1]); err == nil {
				update(v)
			} else {
				update(x[1])
			}
		} else {
			update(true)
		}
	}
	return MakeMap(m)
}

// ParseEnv retuns the environment as a params
func ParseEnv() Map {
	env := strings.Join(os.Environ(), " ")
	return ParseString(env)
}
