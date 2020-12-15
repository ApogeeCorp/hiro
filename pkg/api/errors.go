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

	"github.com/spf13/cast"
)

var (
	// ErrBadRequest should be returned for a bad request or invalid parameters
	ErrBadRequest = Errorf("bad request").WithStatus(http.StatusBadRequest)

	// ErrUnauthorized is returned when authentication has failed or is necessary
	ErrUnauthorized = Errorf("access denied").WithStatus(http.StatusUnauthorized)

	// ErrForbidden should be returned when an client is authenticated but not allowed
	ErrForbidden = Errorf("forbidden").WithStatus(http.StatusForbidden)

	// ErrNotFound is returned when an object is not found
	ErrNotFound = Errorf("not found").WithStatus(http.StatusNotFound)

	// ErrConflict should be returned when there is a conflict with resources
	ErrConflict = Errorf("conflict").WithStatus(http.StatusConflict)

	// ErrServerError should be returned for internal errors
	ErrServerError = Errorf("server error").WithStatus(http.StatusInternalServerError)
)

type (
	// ErrorResponse is response with an error
	ErrorResponse interface {
		error
		Responder

		// Detail returns the detail
		Detail() []string

		// With error overrides the existing error if the status is greater, or sets the detail
		WithError(err error) ErrorResponse

		// WithMessage sets the message for the error
		WithMessage(format string, args ...interface{}) ErrorResponse

		// WithStatus sets the status code for the error
		WithStatus(status int) ErrorResponse

		// WithDetail adds detail to the error
		WithDetail(detail ...interface{}) ErrorResponse
	}

	statusError struct {
		err    error
		status int
		detail []string
	}
)

// Error returns a new api error from the error
func Error(err error) ErrorResponse {
	e := &statusError{
		status: http.StatusInternalServerError,
		err:    err,
	}

	var r ErrorResponse

	if errors.As(err, &r) {
		e.status = r.Status()
	}

	return e
}

// Errorf returns a new api error from the string
func Errorf(format string, args ...interface{}) ErrorResponse {
	e := &statusError{
		err:    fmt.Errorf(format, args...),
		status: http.StatusInternalServerError,
	}

	return e
}

func (e statusError) Error() string {
	return e.err.Error()
}

func (e statusError) WithDetail(detail ...interface{}) ErrorResponse {
	if e.detail == nil {
		e.detail = make([]string, 0)
	}

	for _, d := range detail {
		switch t := d.(type) {
		case error:
			e.detail = append(e.detail, t.Error())

		case string:
			e.detail = append(e.detail, t)

		default:
			e.detail = append(e.detail, cast.ToString(t))
		}
	}

	return &e
}

func (e statusError) WithMessage(format string, args ...interface{}) ErrorResponse {
	e.err = fmt.Errorf(format, args...)
	return &e
}

func (e statusError) WithStatus(status int) ErrorResponse {
	e.status = status
	return &e
}

func (e statusError) WithError(err error) ErrorResponse {
	var r ErrorResponse

	if errors.As(err, &r) {
		if r.Status() <= e.status {
			if e.Error() != r.Error() {
				e.detail = append(e.detail, r.Error())
			}
			e.detail = append(e.detail, r.Detail()...)
		}
		if r.Status() > e.status {
			e.err = r
			e.status = r.Status()
		}
	} else {
		e.detail = append(e.detail, err.Error())
	}

	return &e
}

func (e statusError) Payload() interface{} {
	return struct {
		Message string   `json:"message"`
		Detail  []string `json:"detail,omitempty"`
	}{
		Message: e.Error(),
		Detail:  e.detail,
	}
}

func (e statusError) Write(w http.ResponseWriter) error {
	return WriteJSON(w, e.status, e.Payload())
}

func (e statusError) Status() int {
	return e.status
}

func (e statusError) Detail() []string {
	return e.detail
}
