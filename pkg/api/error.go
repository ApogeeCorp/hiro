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

package api

import (
	"errors"
	"fmt"
	"net/http"
)

// Error returns an error responder
func Error(e error) *Response {
	var r Responder

	if errors.As(e, &r) {
		return NewResponse(r.Payload()).WithStatus(r.Status())
	}

	p := struct {
		Message string `json:"message"`
	}{
		Message: e.Error(),
	}

	return NewResponse(p).WithStatus(http.StatusInternalServerError)
}

// Errorf returns a new error response from a string
func Errorf(f string, args ...interface{}) *Response {
	p := struct {
		Message string `json:"message"`
	}{
		Message: fmt.Sprintf(f, args...),
	}

	return NewResponse(p).WithStatus(http.StatusInternalServerError)
}

// StatusError sets the status and error message in one go
func StatusError(status int, e error) *Response {
	return Error(e).WithStatus(status)
}

// StatusErrorf sets the status and error message in one go
func StatusErrorf(status int, f string, args ...interface{}) *Response {
	return Errorf(f, args...).WithStatus(status)
}
