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
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"

	"github.com/spf13/cast"
)

type (
	// Responder is an api response interface
	Responder interface {
		// Status returns the http status
		Status() int

		// Payload is the payload
		Payload() interface{}

		// Write writes ou the payload
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
	switch p.(type) {
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

// Redirect will set the proper redirect headers and http.StatusFound
func Redirect(u *url.URL, args ...map[string]string) *Response {
	r := NewResponse()

	q := u.Query()

	for _, a := range args {
		for k, v := range a {
			q.Set(k, v)
		}
	}

	u.RawQuery = q.Encode()

	r.header.Set("Location", u.String())

	r.status = http.StatusFound

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
