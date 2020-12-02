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

package ptr

import "github.com/spf13/cast"

// SafeString handles nil pointers to always return a valid string
func SafeString(s interface{}, def ...string) string {
	val := cast.ToString(s)
	if val == "" && len(def) > 0 {
		return def[0]
	}
	return val
}

// SafeBool returns a safe bool from the value
func SafeBool(b interface{}, def ...bool) bool {
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

// SafeInt64 returns a safe int64 from the value or default if nil
func SafeInt64(i interface{}, def ...int64) int64 {
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

// SafeStrEqual compares to values as strings safely
func SafeStrEqual(s1, s2 interface{}) bool {
	return SafeString(s1) == SafeString(s2)
}
