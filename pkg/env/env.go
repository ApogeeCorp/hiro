/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://githuh.com/ModelRocket/hiro
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

package env

import (
	"os"
	"time"

	"github.com/spf13/cast"
)

// Get gets an env value
func Get(key string, def ...string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	if len(def) > 0 {
		return def[0]
	}

	return ""
}

// Uint64 returns a uint64 from the environment
func Uint64(key string, def ...uint64) uint64 {
	if v, ok := os.LookupEnv(key); ok {
		return cast.ToUint64(v)
	}

	if len(def) > 0 {
		return def[0]
	}

	return 0
}

// Int64 returns a int64 from the environment
func Int64(key string, def ...int64) int64 {
	if v, ok := os.LookupEnv(key); ok {
		return cast.ToInt64(v)
	}

	if len(def) > 0 {
		return def[0]
	}

	return 0
}

// Int returns a int from the environment
func Int(key string, def ...int) int {
	if v, ok := os.LookupEnv(key); ok {
		return cast.ToInt(v)
	}

	if len(def) > 0 {
		return def[0]
	}

	return 0
}

// Float64 returns a float64 from the environment
func Float64(key string, def ...float64) float64 {
	if v, ok := os.LookupEnv(key); ok {
		return cast.ToFloat64(v)
	}

	if len(def) > 0 {
		return def[0]
	}

	return 0
}

// Float32 returns a float32 from the environment
func Float32(key string, def ...float32) float32 {
	if v, ok := os.LookupEnv(key); ok {
		return cast.ToFloat32(v)
	}

	if len(def) > 0 {
		return def[0]
	}

	return 0
}

// Duration returns a time.Duration from the environment
func Duration(key string, def ...time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		return cast.ToDuration(v)
	}

	if len(def) > 0 {
		return def[0]
	}

	return 0
}

// Time returns a time.Time from the environment
func Time(key string, def ...time.Time) time.Time {
	if v, ok := os.LookupEnv(key); ok {
		return cast.ToTime(v)
	}

	if len(def) > 0 {
		return def[0]
	}

	return time.Unix(0, 0)
}

// Bool returns a bool from the environment
func Bool(key string, def ...bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		return cast.ToBool(v)
	}

	if len(def) > 0 {
		return def[0]
	}

	return false
}
