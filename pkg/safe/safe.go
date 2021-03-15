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

// Uint64 returns a safe uint64 from the value or default if nil
func Uint64(i interface{}, def ...uint64) uint64 {
	switch t := i.(type) {
	case uint64:
		return t
	case *uint64:
		if t == nil {
			if len(def) > 0 {
				return def[0]
			}
			break
		}
		return *t
	}

	return cast.ToUint64(i)
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
