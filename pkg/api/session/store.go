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

package session

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type (
	store struct {
		Controller
		ctx     context.Context
		codecs  []securecookie.Codec
		options *sessions.Options
		aud     string
		sub     string
	}
)

// Get Fetches a session for a given name after it has been added to the
// registry.
func (s *store) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a new session for the given name without adding it to the registry.
func (s *store) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	if session == nil {
		return nil, nil
	}

	opts := *s.options
	session.Options = &(opts)
	session.IsNew = true

	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.codecs...)
		if err == nil {
			err = s.load(session)
			if err == nil {
				session.IsNew = false
			} else if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrSessionExpired) {
				err = nil
			}
		}
	}

	s.MaxAge(s.options.MaxAge)

	return session, err
}

// Save saves the given session into the database and deletes cookies if needed
func (s *store) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Set delete if max-age is < 0
	if session.Options.MaxAge < 0 {
		if err := s.SessionDestroy(s.ctx, string(session.ID)); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	if err := s.save(session); err != nil {
		return err
	}

	// Keep the session ID key in a cookie so it can be looked up in DB later.
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.codecs...)
	if err != nil {
		return err
	}

	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
func (s *store) MaxAge(age int) {
	s.options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range s.codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// MaxLength restricts the maximum length of new sessions to l.
func (s *store) MaxLength(l int) {
	for _, c := range s.codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

// load fetches a session by ID from the database and decodes its content
// into session.Values.
func (s *store) load(session *sessions.Session) error {
	sess, err := s.SessionLoad(s.ctx, string(session.ID))
	if err != nil {
		return err
	}

	return securecookie.DecodeMulti(session.Name(), string(sess.Data), &session.Values, s.codecs...)
}

// save writes encoded session.Values to a database record.
// writes to http_sessions table by default.
func (s *store) save(session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.codecs...)
	if err != nil {
		return err
	}

	exOn := session.Values["expires_on"]

	var expiresAt time.Time

	if exOn == nil {
		expiresAt = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))
	} else {
		expiresAt = exOn.(time.Time)
		if expiresAt.Sub(time.Now().Add(time.Second*time.Duration(session.Options.MaxAge))) < 0 {
			expiresAt = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))
		}
	}

	sess := &Session{
		ID:        string(session.ID),
		Audience:  s.aud,
		Subject:   s.sub,
		Data:      encoded,
		ExpiresAt: expiresAt,
	}

	if session.IsNew {
		err = s.SessionCreate(s.ctx, sess)
		session.ID = sess.ID
	} else {
		err = s.SessionUpdate(s.ctx, sess)
	}

	return err
}
