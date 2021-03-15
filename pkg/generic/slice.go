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
	"reflect"

	"github.com/spf13/cast"
)

// Slice is a generic slice manipulation interface helper
type Slice interface {
	Append(vals ...interface{}) Slice
	Insert(index int, val interface{}) Slice
	IndexOf(val interface{}) int
	Len() int
	Get(index int) interface{}
	Remove(index int) Slice
	Filter(func(index int, val interface{}) bool) Slice
	ForEach(func(index int, val interface{}))
	Map(out interface{}, filters ...MapFilter)
	ToMap() Map
	Contains(values ...interface{}) bool
	ContainsAny(values ...interface{}) bool
}

type slice struct {
	v reflect.Value
}

// MapFilter returns true and the key and value, or false if the value should be skipped
type MapFilter func(index int, val interface{}) (string, interface{}, bool)

// MakeSlice returns a slicer object from a slice
func MakeSlice(s interface{}) Slice {
	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	} else {
		panic("value is not a pointer")
	}
	return &slice{
		v: val,
	}
}

func (s *slice) Append(vals ...interface{}) Slice {
	for _, val := range vals {
		s.v.Set(reflect.Append(s.v, reflect.ValueOf(val)))
	}

	return s
}

func (s *slice) Insert(index int, val interface{}) Slice {
	s.v.Set(reflect.AppendSlice(s.v.Slice(0, index+1), s.v.Slice(index, s.v.Len())))
	s.v.Index(index).Set(reflect.ValueOf(val))

	return s
}

func (s *slice) Len() int {
	return s.v.Len()
}

func (s *slice) Remove(index int) Slice {
	s.v.Set(reflect.AppendSlice(s.v.Slice(0, index), s.v.Slice(index+1, s.v.Len())))
	return s
}

func (s *slice) ForEach(foreach func(index int, val interface{})) {
	for i := 0; i < s.v.Len(); i++ {
		foreach(i, s.v.Index(i).Interface())
	}
}

func (s *slice) Filter(filter func(index int, val interface{}) bool) Slice {

	compSlice := reflect.MakeSlice(s.v.Type(), 0, s.v.Len())

	for i := 0; i < s.v.Len(); i++ {
		if filter(i, s.v.Index(i).Interface()) {
			compSlice = reflect.Append(compSlice, s.v.Index(i))
		}
	}

	s.v.Set(compSlice)

	return s
}

// Map maps the slice to the destination using the filters
// Destination can be a slice or a map
func (s *slice) Map(out interface{}, filters ...MapFilter) {
	rval := reflect.ValueOf(out)
	if rval.Kind() != reflect.Ptr {
		panic("out value must be pointer")
	}
	rval = rval.Elem()

	for _, filter := range filters {
		for i := 0; i < s.v.Len(); i++ {
			if k, v, skip := filter(i, s.v.Index(i).Interface()); !skip {
				switch rval.Kind() {
				case reflect.Slice:
					MakeSlice(out).Append(v)
				case reflect.Map:
					MakeMap(out).Set(k, v)
				}
			}
		}
	}
}

func (s *slice) ToMap() Map {
	rval := make(map[string]interface{})
	for i := 0; i < s.v.Len(); i++ {
		rval[cast.ToString(i)] = s.v.Index(i).Interface()
	}
	return MakeMap(rval)
}

func (s *slice) IndexOf(val interface{}) int {
	for i := 0; i < s.v.Len(); i++ {
		if reflect.DeepEqual(s.v.Index(i).Interface(), val) {
			return i
		}
	}

	return -1
}

func (s *slice) Get(index int) interface{} {
	if index >= s.v.Len() {
		return nil
	}

	val := s.v.Index(index)
	if !val.CanInterface() || val.IsNil() {
		return nil
	}
	return val.Interface()
}

func (s *slice) Contains(values ...interface{}) bool {
	for _, val := range values {
		if s.IndexOf(val) < 0 {
			return false
		}
	}
	return true
}

func (s *slice) ContainsAny(values ...interface{}) bool {
	for _, val := range values {
		if s.IndexOf(val) >= 0 {
			return true
		}
	}
	return false
}
