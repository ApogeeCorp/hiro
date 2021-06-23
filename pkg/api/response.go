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
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cast"
)

type (
	// Responder is an api response interface
	Responder interface {
		// Status returns the http status
		Status() int

		// Payload is the payload
		Payload() interface{}

		// Write writes out the payload
		Write(w http.ResponseWriter) error
	}

	// WriterFunc is a response writer
	WriterFunc func(w http.ResponseWriter, status int, payload interface{}, headers ...http.Header) error

	// Response is the common response type
	Response struct {
		status  int
		payload interface{}
		writer  WriterFunc
		header  http.Header
	}

	// Redirector defines an api redirect
	Redirector struct {
		*Response
		loc *url.URL
	}

	// Encoder is a response encoder
	Encoder interface {
		Encode(w io.Writer) error
	}
)

// NewResponse returns a response with defaults
func NewResponse(payload ...interface{}) *Response {
	var p interface{}
	if len(payload) > 0 {
		p = payload[0]
	}

	var writer WriterFunc
	switch r := p.(type) {
	case Responder:
		return NewResponse(r.Payload()).WithStatus(r.Status())

	case error:
		p := struct {
			Message string `json:"message"`
		}{
			Message: r.Error(),
		}

		return NewResponse(p).WithStatus(http.StatusInternalServerError)

	case []byte:
		writer = Write
	case string:
		writer = Write
	case Encoder:
		writer = Write
	case io.Reader:
		writer = Write
	default:
		writer = WriteJSON
	}

	return &Response{
		status:  http.StatusOK,
		payload: p,
		writer:  writer,
		header:  make(http.Header),
	}
}

// WithStatus sets the status
func (r *Response) WithStatus(status int) *Response {
	r.status = status
	return r
}

// WithHeader adds headers to the request
func (r *Response) WithHeader(key string, value string) *Response {
	r.header.Add(key, value)
	return r
}

// WithWriter sets the writer
func (r *Response) WithWriter(w WriterFunc) *Response {
	r.writer = w
	return r
}

// Status returns the status
func (r *Response) Status() int {
	return r.status
}

// Payload returns the payload
func (r *Response) Payload() interface{} {
	return r.payload
}

// Write writes the response to the writer
func (r *Response) Write(w http.ResponseWriter) error {
	if len(r.header) > 0 {
		for key, vals := range r.header {
			for _, val := range vals {
				w.Header().Add(key, val)
			}
		}
	}

	if r.payload == nil {
		w.WriteHeader(r.status)
		return nil
	}
	return r.writer(w, r.status, r.payload)
}

// RedirectIf does a conditional redirect
func RedirectIf(cond bool, u *url.URL, val ...interface{}) Responder {
	if cond {
		return Redirect(u)
	}

	status := http.StatusOK

	if len(val) < 0 {
		status = http.StatusNoContent
	}

	return NewResponse(val...).WithStatus(status)
}

// RedirectErrIf does a conditional redirect with the error
func RedirectErrIf(cond bool, u *url.URL, err error) Responder {
	if cond {
		return Redirect(u).WithError(err)
	}

	return Error(err)
}

// Redirect will set the proper redirect headers and http.StatusFound
func Redirect(u *url.URL) *Redirector {
	r := &Redirector{
		Response: NewResponse(),
		loc:      u,
	}

	r.header.Set("Location", u.String())

	r.status = http.StatusFound

	return r
}

func (r *Redirector) WithQuery(vals *url.Values) *Redirector {
	r.loc.RawQuery = vals.Encode()

	r.header.Set("Location", r.loc.String())

	return r
}

func (r *Redirector) WithError(err error) *Redirector {
	q := r.loc.Query()

	switch t := err.(type) {
	case ErrorResponse:
		q.Set("error", t.Code())
		q.Set("error_description", t.Error())

		for _, detail := range t.Detail() {
			q.Add("error_detail", detail)
		}
		if detail := t.Detail(); len(detail) > 0 {
			q.Set("error_detail", strings.Join(detail, ","))
		}

	case error:
		e := Error(err)

		q.Set("error", e.Code())
		q.Set("error_description", e.Error())
	}

	r.loc.RawQuery = q.Encode()

	r.header.Set("Location", r.loc.String())

	return r
}

// WriteJSON writes json objects
func WriteJSON(w http.ResponseWriter, status int, payload interface{}, headers ...http.Header) error {
	if len(headers) > 0 {
		for key, vals := range headers[0] {
			for _, val := range vals {
				w.Header().Add(key, val)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if enc, ok := payload.(Encoder); ok {
		return enc.Encode(w)
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	return enc.Encode(payload)
}

// WriteXML writes an  object out as XML
func WriteXML(w http.ResponseWriter, status int, payload interface{}, headers ...http.Header) error {
	if len(headers) > 0 {
		for key, vals := range headers[0] {
			for _, val := range vals {
				w.Header().Add(key, val)
			}
		}
	}

	w.Header().Set("Content-Type", "application/xml")

	w.WriteHeader(status)

	if enc, ok := payload.(Encoder); ok {
		return enc.Encode(w)
	}

	enc := xml.NewEncoder(w)

	return enc.Encode(payload)
}

// Write writes the raw payload out expeting it to be bytes
func Write(w http.ResponseWriter, status int, payload interface{}, headers ...http.Header) error {
	if len(headers) > 0 {
		for key, vals := range headers[0] {
			for _, val := range vals {
				w.Header().Add(key, val)
			}
		}
	}

	w.WriteHeader(status)

	if closer, ok := payload.(io.Closer); ok {
		defer closer.Close()
	}

	switch data := payload.(type) {
	case []byte:
		if _, err := w.Write(data); err != nil {
			return err
		}
	case string:
		if _, err := w.Write([]byte(data)); err != nil {
			return err
		}
	case Encoder:
		if err := data.Encode(w); err != nil {
			return err
		}
	case io.Reader:
		if l := w.Header().Get("Content-Length"); l != "" {
			if _, err := io.CopyN(w, data, cast.ToInt64(l)); err != nil {
				return err
			}
		} else {
			if _, err := io.Copy(w, data); err != nil {
				return err
			}
		}
	}

	return nil
}
