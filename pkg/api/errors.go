/*************************************************************************
 * MIT License
 * Copyright (c) 2021 Model Rocket
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

package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/cast"
	"github.com/stoewer/go-strcase"
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

	// ErrAuthUnacceptable should be returned when an authorizer could not find data to decode
	ErrAuthUnacceptable = Errorf("no acceptable authorization data found").WithCode("unacceptable").WithStatus(http.StatusUnauthorized)

	// ErrNotImplemented is returned when a method is not implemented
	ErrNotImplemented = Errorf("operation is not implemented").WithCode("not_implemented").WithStatus(http.StatusNotImplemented)

	// ErrTimeout is returned when a request or operation times out
	ErrTimeout = Errorf("timeout").WithStatus(http.StatusRequestTimeout)
)

type (
	// ErrorResponse is response with an error
	ErrorResponse interface {
		error
		Responder

		// Code returns the error code
		Code() string

		// Detail returns the detail
		Detail() []string

		// With error overrides the existing error if the status is greater, or sets the detail
		WithError(err error) ErrorResponse

		// WithMessage sets the message for the error
		WithMessage(format string, args ...interface{}) ErrorResponse

		// WithStatus sets the status code for the error
		WithStatus(status int) ErrorResponse

		// WithCode sets the error code for the response, the default is the http status
		WithCode(code string) ErrorResponse

		// WithDetail adds detail to the error
		WithDetail(detail ...interface{}) ErrorResponse
	}

	// StatusError is a basic status error others can sub
	StatusError struct {
		err    error
		status int
		code   string
		detail []string
	}
)

// Error returns a new api error from the error
func Error(err error) ErrorResponse {
	e := &StatusError{
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
	e := &StatusError{
		err:    fmt.Errorf(format, args...),
		status: http.StatusInternalServerError,
	}

	return e
}

func (e StatusError) Error() string {
	return e.err.Error()
}

// WithStatus returns the error with status
func (e StatusError) WithStatus(status int) ErrorResponse {
	e.status = status
	return &e
}

// WithError returns the error with an underlying error
func (e StatusError) WithError(err error) ErrorResponse {
	return e.WithMessage(err.Error())
}

// WithMessage returns the error with a message
func (e StatusError) WithMessage(format string, args ...interface{}) ErrorResponse {
	msg := fmt.Errorf(format, args...)

	e.err = fmt.Errorf("%w: %s", e.err, msg)

	return &e
}

// WithCode sets the error code for the response, the default is the http status
func (e StatusError) WithCode(code string) ErrorResponse {
	e.code = code
	return &e
}

// WithDetail returns the error with detail
func (e StatusError) WithDetail(detail ...interface{}) ErrorResponse {
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

// Payload implements the api.Responder interface
func (e StatusError) Payload() interface{} {
	return struct {
		Error       string   `json:"error"`
		Description string   `json:"error_description,omitempty"`
		Detail      []string `json:"error_detail,omitempty"`
	}{
		Error:       e.Code(),
		Description: e.Error(),
		Detail:      e.detail,
	}
}

// Code returns the error code
func (e StatusError) Code() string {
	if e.code != "" {
		return e.code
	}
	return strcase.SnakeCase(http.StatusText(e.status))
}

// Write implements the api.Responder interface
func (e StatusError) Write(w http.ResponseWriter) error {
	return WriteJSON(w, e.status, e.Payload())
}

// Status implements the api.Responder interface
func (e StatusError) Status() int {
	return e.status
}

// Detail returns the error detail
func (e StatusError) Detail() []string {
	return e.detail
}

// Is implements the errors.Is interface
func (e *StatusError) Is(target error) bool {
	t, ok := target.(*StatusError)
	if !ok {
		return false
	}

	if is := errors.Is(e.err, t.err); is {
		return is
	}

	return t.status == e.status
}
