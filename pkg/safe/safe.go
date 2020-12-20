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

// Package safe returns a safe scalar value from a possible nil pointer
package safe

import (
	"time"

	"github.com/spf13/cast"
)

// String handles nil pointers to always return a valid string
func String(s interface{}, def ...interface{}) string {
	val := cast.ToString(s)
	if val == "" && len(def) > 0 {
		return cast.ToString(def[0])
	}
	return val
}

// Bool returns a safe bool from the value
func Bool(b interface{}, def ...bool) bool {
	switch t := b.(type) {
	case bool:
		return t
	case *bool:
		if t == nil {
			if len(def) > 0 {
				return def[0]
			}
			break
		}
		return *t
	}

	return cast.ToBool(b)
}

// Int64 returns a safe int64 from the value or default if nil
func Int64(i interface{}, def ...int64) int64 {
	switch t := i.(type) {
	case int64:
		return t
	case *int64:
		if t == nil {
			if len(def) > 0 {
				return def[0]
			}
			break
		}
		return *t
	}

	return cast.ToInt64(i)
}

// Int returns a safe int64 from the value or default if nil
func Int(i interface{}, def ...int) int {
	switch t := i.(type) {
	case int:
		return t
	case *int:
		if t == nil {
			if len(def) > 0 {
				return def[0]
			}
			break
		}
		return *t
	}

	return cast.ToInt(i)
}

// StrEqual compares to values as strings safely
func StrEqual(s1, s2 interface{}) bool {
	return String(s1) == String(s2)
}

// Time returns a safe time
func Time(t interface{}, def ...time.Time) time.Time {
	val := cast.ToTime(t)

	if val.IsZero() && len(def) > 0 {
		return def[0]
	}

	return val
}
