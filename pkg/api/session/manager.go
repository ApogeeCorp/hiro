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

package session

import (
	"context"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
)

type (
	// Manager store is a session store
	Manager struct {
		Controller
		optionCache *cache.Cache
	}
)

// NewManager gets a store manager
func NewManager(ctrl Controller) *Manager {
	return &Manager{
		Controller:  ctrl,
		optionCache: cache.New(time.Minute*30, time.Minute*60),
	}
}

// GetStore gets a store for the given context
func (s *Manager) GetStore(ctx context.Context, aud string, sub ...string) (sessions.Store, error) {
	var opts *Options

	if c, ok := s.optionCache.Get(aud); ok {
		opts = c.(*Options)
	} else {
		o, err := s.SessionOptions(ctx, aud)
		if err != nil {
			return nil, err
		}

		opts = &o

		opts.codecs = securecookie.CodecsFromPairs(opts.KeyPairs...)

		s.optionCache.Set(aud, opts, cache.DefaultExpiration)
	}

	var _sub string

	if len(sub) > 0 {
		_sub = sub[0]
	}

	return &store{
		Controller: s.Controller,
		ctx:        ctx,
		options:    &opts.Options,
		aud:        aud,
		sub:        _sub,
		codecs:     opts.codecs,
	}, nil
}
