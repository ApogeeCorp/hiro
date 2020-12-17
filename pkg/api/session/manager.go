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
	"time"

	"github.com/ModelRocket/hiro/pkg/types"
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
func (s *Manager) GetStore(ctx context.Context, aud types.ID, sub ...types.ID) (sessions.Store, error) {
	var opts *Options

	if c, ok := s.optionCache.Get(aud.String()); ok {
		opts = c.(*Options)
	} else {
		o, err := s.SessionOptions(ctx, aud)
		if err != nil {
			return nil, err
		}

		opts = &o

		opts.codecs = securecookie.CodecsFromPairs(opts.Hash[:], opts.Block[:])

		s.optionCache.Set(aud.String(), opts, cache.DefaultExpiration)
	}

	var _sub types.ID

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
