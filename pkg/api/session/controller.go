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

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type (
	// Controller represents the backend session storage interface
	Controller interface {
		// SessionLoad loads a session by id
		SessionLoad(ctx context.Context, id string) (Session, error)

		// SessionCreate creates a session
		SessionCreate(ctx context.Context, session *Session) error

		// SessionUpdate updates a session
		SessionUpdate(ctx context.Context, session *Session) error

		// SessionDestroy destroys a session by id
		SessionDestroy(ctx context.Context, id string) error

		// SessionOptions returns the options from the audience
		SessionOptions(ctx context.Context, aud string) (Options, error)

		// SessionCleanup should remove expired sessions from the store
		SessionCleanup(ctx context.Context) error
	}

	// Options provide cookie hashing and encryption
	Options struct {
		sessions.Options
		KeyPairs [][]byte
		codecs   []securecookie.Codec
	}
)
