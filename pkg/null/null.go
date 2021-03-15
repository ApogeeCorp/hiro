/*************************************************************************
 * MIT License
 * Copyright (c) 2019 Model Rocket
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

// Package null provides some clean helpers for sql NULL value handling
package null

import (
	"database/sql"
	"reflect"
	"time"

	"github.com/spf13/cast"
)

// String safely converts s to a sql.NullString
func String(s interface{}) sql.NullString {
	switch t := s.(type) {
	case string:
		return sql.NullString{Valid: true, String: t}

	case *string:
		if t == nil {
			return sql.NullString{Valid: false}
		}
		return sql.NullString{Valid: true, String: *t}
	}

	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Ptr && val.IsNil() {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{Valid: true, String: cast.ToString(s)}
}

// Int64 safely converts i to a sql.NullInt64
func Int64(i interface{}) sql.NullInt64 {
	switch t := i.(type) {
	case int64:
		return sql.NullInt64{Valid: true, Int64: t}

	case *int64:
		if t == nil {
			return sql.NullInt64{Valid: false}
		}
		return sql.NullInt64{Valid: true, Int64: *t}
	}

	val := reflect.ValueOf(i)
	if val.Kind() == reflect.Ptr && val.IsNil() {
		return sql.NullInt64{Valid: false}
	}
	return sql.NullInt64{Valid: true, Int64: cast.ToInt64(i)}
}

// Timer is time interface
type Timer interface {
	Time() time.Time
}

// Time safely converts tm to a sql.NullTime
func Time(tm interface{}) sql.NullTime {
	switch t := tm.(type) {
	case time.Time:
		return sql.NullTime{Valid: !t.IsZero(), Time: t}

	case *time.Time:
		if t == nil {
			return sql.NullTime{Valid: false}
		}
		return sql.NullTime{Valid: !t.IsZero(), Time: *t}

	case Timer:
		if t == nil {
			return sql.NullTime{Valid: false}
		}
		_t := t.Time()
		return sql.NullTime{Valid: !_t.IsZero(), Time: _t}
	}

	val := reflect.ValueOf(tm)
	if val.Kind() == reflect.Ptr && val.IsNil() {
		return sql.NullTime{Valid: false}
	}
	t := cast.ToTime(tm)
	return sql.NullTime{Valid: !t.IsZero(), Time: t}
}

// Bool safely converts b to a sql.NullBool
func Bool(b interface{}) sql.NullBool {
	switch t := b.(type) {
	case bool:
		return sql.NullBool{Valid: true, Bool: t}

	case *bool:
		if t == nil {
			return sql.NullBool{Valid: false}
		}
		return sql.NullBool{Valid: true, Bool: *t}
	}

	val := reflect.ValueOf(b)
	if val.Kind() == reflect.Ptr && val.IsNil() {
		return sql.NullBool{Valid: false}
	}
	return sql.NullBool{Valid: true, Bool: cast.ToBool(b)}
}
