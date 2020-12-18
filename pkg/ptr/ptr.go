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

// Package ptr provides a set of SQL compatible pointer helpers
package ptr

import (
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

// String returns s safely as *string
func String(s interface{}) *string {
	return Pointer(s).String()
}

// NilString returns s safely as *string
// If string is empty "", nil is returned
func NilString(s interface{}) *string {
	return Pointer(s).NilString()
}
