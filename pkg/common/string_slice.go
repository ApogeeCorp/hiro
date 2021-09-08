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

package common

import (
	"reflect"
	"strings"

	"github.com/ModelRocket/hiro/pkg/generic"
	"github.com/spf13/cast"
)

type (
	// StringSlice is helper for the common []string
	StringSlice []string
)

// Append returns a slice with the values appended
func (s StringSlice) Append(vals ...interface{}) generic.Slice {
	rval := s

	for _, v := range vals {
		rval = append(rval, cast.ToString(v))
	}

	return rval
}

// Insert returns a slice with the value appended at the index
func (s StringSlice) Insert(index int, val interface{}) generic.Slice {
	return s
}

// IndexOf returns the index of the value in the slice, or -1 if not found
func (s StringSlice) IndexOf(val interface{}) int {
	v := cast.ToString(val)

	for i := range s {
		if s[i] == v {
			return i
		}
	}

	return -1
}

// Len returns the length of the slice
func (s StringSlice) Len() int {
	return len(s)
}

// Empty returns true if the slice is empty
func (s StringSlice) Empty() bool {
	return len(s) == 0
}

// Get returns the item at the index
func (s StringSlice) Get(index int) interface{} {
	if index < 0 || index >= len(s) {
		return nil
	}
	return s[index]
}

// Remove returns a slice with the value removed at the index
func (s StringSlice) Remove(index int) generic.Slice {
	if index < 0 || index >= len(s) {
		return s
	}

	return append(s[:index], s[index+1:]...)
}

// Filter filters the slice based on the filter method
func (s StringSlice) Filter(f func(index int, val interface{}) bool) generic.Slice {
	rval := make(StringSlice, 0)

	for i, v := range s {
		if f(i, v) {
			rval = append(rval, v)
		}
	}

	return rval
}

// ForEach iterates over the slice
func (s StringSlice) ForEach(f func(index int, val interface{})) {
	for i, v := range s {
		f(i, v)
	}
}

// Map converts the slice to a map
func (s StringSlice) Map(out interface{}, filters ...generic.MapFilter) {
	rval := reflect.ValueOf(out)
	if rval.Kind() != reflect.Ptr {
		panic("out value must be pointer")
	}
	rval = rval.Elem()

	for _, filter := range filters {
		for i, v := range s {
			if k, v, skip := filter(i, v); !skip {
				switch rval.Kind() {
				case reflect.Slice:
					generic.MakeSlice(out).Append(v)
				case reflect.Map:
					generic.MakeMap(out).Set(k, v)
				}
			}
		}
	}
}

// ToMap converts the slice to an index map
func (s StringSlice) ToMap() generic.Map {
	rval := make(Map)

	for i, v := range s {
		rval[cast.ToString(i)] = v
	}

	return rval
}

// Contains returns true of the slice contains all of the values
func (s StringSlice) Contains(values ...interface{}) bool {
	for _, elem := range values {
		contains := false

		for _, v := range s {
			if string(v) == cast.ToString(elem) {
				contains = true
			}
		}

		if !contains {
			return false
		}
	}

	return true
}

// Contains returns true of the slice contains all of the values
func (s StringSlice) ContainsPrefix(values ...interface{}) bool {
	for _, elem := range values {
		contains := false

		for _, v := range s {
			val := cast.ToString(elem)

			if string(v) == val {
				contains = true
			}

			if strings.HasPrefix(string(v), val+".") {
				contains = true
			}
		}

		if !contains {
			return false
		}
	}

	return true
}

// ContainsAny returns true of the slice contains any of the values
func (s StringSlice) ContainsAny(values ...interface{}) bool {
	for _, elem := range values {
		for _, v := range s {
			if string(v) == cast.ToString(elem) {
				return true
			}
		}
	}
	return false
}

// ContainsAny returns true of the slice contains any of the values
func (s StringSlice) ContainsAnyPrefix(values ...interface{}) bool {
	for _, elem := range values {
		for _, v := range s {
			val := cast.ToString(elem)

			if string(v) == val {
				return true
			}

			if strings.HasPrefix(string(v), val+".") {
				return true
			}
		}
	}
	return false
}

// Unique returns a scope withonly unique values
func (s StringSlice) Unique() StringSlice {
	p := make(StringSlice, 0)

	for _, v := range s {
		if !p.Contains(v) {
			p = append(p, v)
		}
	}

	return p
}

// FilterPrefix returns the expand list filtered on the prefix
func (s StringSlice) FilterPrefix(prefix string) StringSlice {
	rval := make(StringSlice, 0)

	if !strings.HasSuffix(prefix, ".") {
		prefix = prefix + "."
	}

	for _, v := range s {
		if strings.HasPrefix(v, prefix) {
			rval = append(rval, strings.TrimPrefix(v, prefix))
		}
	}

	return rval
}
