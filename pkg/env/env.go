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
