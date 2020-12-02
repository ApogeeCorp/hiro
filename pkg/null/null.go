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

// Time safely converts tm to a sql.NullTime
func Time(tm interface{}) sql.NullTime {
	switch t := tm.(type) {
	case time.Time:
		return sql.NullTime{Valid: true, Time: t}

	case *time.Time:
		if t == nil {
			return sql.NullTime{Valid: false}
		}
		return sql.NullTime{Valid: true, Time: *t}
	}

	val := reflect.ValueOf(tm)
	if val.Kind() == reflect.Ptr && val.IsNil() {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Valid: true, Time: cast.ToTime(tm)}
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
