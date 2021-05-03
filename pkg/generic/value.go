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

package generic

import (
	"encoding/json"
	"time"

	"github.com/spf13/cast"
)

// Value defines a simple casting interface
type Value interface {
	String() string
	StringPtr() *string
	StringSlice() []string
	Bool() bool
	Int() int
	Int64() int64
	Uint64() uint64
	Float64() float64
	Slice() []interface{}
	Map() Map
	Duration() time.Duration
	Time() time.Time
	Interface() interface{}
	IsNil() bool
	IsJSONNumber() bool
}

// value defines a value wrapper
type value struct {
	v            interface{}
	isJSONNumber bool
}

// MakeValue returns a new value with cast helpers
func MakeValue(v interface{}) Value {
	rval := value{}

	if v != nil {
		if val, ok := v.(json.Number); ok {
			rval.isJSONNumber = true
			v = string(val)
		}
	}

	rval.v = v

	return rval
}

// IsJSONNumber return true if the original value was a json.Number
func (v value) IsJSONNumber() bool {
	return v.isJSONNumber
}

// String casts the value to a string
func (v value) String() string {
	return cast.ToString(v.v)
}

// StringPtr casts the value to a string pointer
func (v value) StringPtr() *string {
	tmp := cast.ToString(v.v)
	return &tmp
}

// StringSlice casts the value to a string slice
func (v value) StringSlice() []string {
	return cast.ToStringSlice(v.v)
}

// Slice returns the value cast as []interface{}
func (v value) Slice() []interface{} {
	return cast.ToSlice(v.v)
}

// Bool casts the value to a bool
func (v value) Bool() bool {
	return cast.ToBool(v.v)
}

// Int casts the value to an int
func (v value) Int() int {
	return cast.ToInt(v.v)
}

// Int64 casts the value to an int64
func (v value) Int64() int64 {
	return cast.ToInt64(v.v)
}

// Uint64 casts the value to an uint64
func (v value) Uint64() uint64 {
	return cast.ToUint64(v.v)
}

// Float64 casts the value to a float64
func (v value) Float64() float64 {
	return cast.ToFloat64(v.v)
}

// Time casts the value to a time.Time
func (v value) Time() time.Time {
	if v.IsJSONNumber() {
		return time.Unix(cast.ToInt64(v.v), 0)
	}
	return cast.ToTime(v.v)
}

// Duration casts the value to a time.Duration
func (v value) Duration() time.Duration {
	if v.IsJSONNumber() {
		return time.Duration(cast.ToInt64(v.v))
	}
	return cast.ToDuration(v.v)
}

// Interface returns the underlying interface for the value
func (v value) Interface() interface{} {
	if v.IsJSONNumber() {
		return v.Float64()
	}
	return v.v
}

// IsNil returns if the enclosed value is nil
func (v value) IsNil() bool {
	return v.v == nil
}

// Map converts the object to a Map
func (v value) Map() Map {
	return MakeMap(cast.ToStringMap(v.v))
}
