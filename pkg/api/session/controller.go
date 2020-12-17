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

	"github.com/ModelRocket/hiro/pkg/types"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type (
	// Controller represents the backend session storage interface
	Controller interface {
		// SessionLoad loads a session by id
		SessionLoad(ctx context.Context, id types.ID) (Session, error)

		// SessionCreate creates a session
		SessionCreate(ctx context.Context, session *Session) error

		// SessionUpdate updates a session
		SessionUpdate(ctx context.Context, session *Session) error

		// SessionDestroy destroys a session by id
		SessionDestroy(ctx context.Context, id types.ID) error

		// SessionOptions returns the options from the audience
		SessionOptions(ctx context.Context, aud types.ID) (Options, error)

		// SessionCleanup should remove expired sessions from the store
		SessionCleanup(ctx context.Context) error
	}

	// Options provide cookie hashing and encryption
	Options struct {
		sessions.Options
		Hash   [32]byte
		Block  [32]byte
		codecs []securecookie.Codec
	}
)
