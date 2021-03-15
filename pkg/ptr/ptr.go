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

// Package ptr provides a set of SQL compatible pointer helpers
package ptr

import (
	"reflect"
	"time"

	"github.com/spf13/cast"
)

type (
	// Pointers provides casting and de-referencing support for scalar values
	Pointers interface {
		Int() *int
		Int64() *int64
		Bool() *bool
		String() *string
		NilString() *string
		Time() *time.Time
		Duration() *time.Duration
	}

	ptr struct {
		v interface{}
	}
)

var (
	// False is the false pointer
	False = Bool(false)

	// True is the true pointer
	True = Bool(true)
)

// Pointer returns a new Pointers for the value
func Pointer(v interface{}) Pointers {
	return &ptr{v}
}

// Int returns the address of the int
func (p *ptr) Int() *int {
	i := cast.ToInt(p.v)
	return &i
}

// Int64 returns the address of the int64
func (p *ptr) Int64() *int64 {
	i := cast.ToInt64(p.v)
	return &i
}

// Bool returns the address of the bool
func (p *ptr) Bool() *bool {
	b := cast.ToBool(p.v)
	return &b
}

// String returns the address of the string
func (p *ptr) String() *string {
	val := reflect.ValueOf(p.v)
	if val.Kind() == reflect.Ptr && val.IsNil() {
		s := ""
		return &s
	}
	b := cast.ToString(p.v)
	return &b
}

// NilString returns the address of the string but nil if empty
func (p *ptr) NilString() *string {
	b := cast.ToString(p.v)
	if b == "" {
		return nil
	}
	return &b
}

// Time returns the address of the time
func (p *ptr) Time() *time.Time {
	b := cast.ToTime(p.v)
	return &b
}

// Duration returns the address of the time
func (p *ptr) Duration() *time.Duration {
	b := cast.ToDuration(p.v)
	return &b
}

// Int returns i safely as *int
func Int(i interface{}) *int {
	return Pointer(i).Int()
}

// Int64 returns i safely as *int64
func Int64(i interface{}) *int64 {
	return Pointer(i).Int64()
}

// Bool returns s safely as *bool
func Bool(s interface{}) *bool {
	return Pointer(s).Bool()
}

// Time converts t to a *time.Time
func Time(t interface{}) *time.Time {
	return Pointer(t).Time()
}

// Duration converts t to a *time.Duration
func Duration(t interface{}) *time.Duration {
	return Pointer(t).Duration()
}

// String returns s safely as *string
func String(s interface{}) *string {
	return Pointer(s).String()
}

// NilString returns s safely as *string
// If string is empty "", nil is returned
func NilString(s interface{}) *string {
	return Pointer(s).NilString()
}

// First returns the first non-nil ptr
func First(ptrs ...interface{}) interface{} {
	for _, p := range ptrs {
		if p != nil {
			return p
		}
	}

	return nil
}
