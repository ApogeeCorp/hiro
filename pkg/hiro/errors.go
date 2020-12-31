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

package hiro

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/ModelRocket/sparks/pkg/api"
	"github.com/lib/pq"
)

var (
	// ErrDuplicateObject is returned where there is unique constraint violation
	ErrDuplicateObject = api.ErrConflict

	// ErrInputValidation is returned when a object validation fails
	ErrInputValidation = api.ErrBadRequest

	// ErrNotFound is returned when an object is not found
	ErrNotFound = api.ErrNotFound

	// ErrAuthFailed is returned when user authentication fails to due to password mistmatch
	ErrAuthFailed = api.ErrUnauthorized

	// ErrDatabaseTimeout is returned when the database cannot be reached
	ErrDatabaseTimeout = api.ErrServerError.WithDetail("database connection timeout")

	// ErrContextNotFound is returned when hiro is not in the context
	ErrContextNotFound = api.ErrServerError.WithDetail("hiro not found in context")
)

// ParseSQLError provides cleaner errors for database issues
func ParseSQLError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		err = fmt.Errorf("%w", err)
		return fmt.Errorf("%w: %s", err, ErrNotFound)
	}

	if pe, ok := err.(*pq.Error); ok {
		switch pe.Code.Name() {
		case "exclusion_violation":
			fallthrough
		case "unique_violation":
			return fmt.Errorf("%w [%s.%s]: %s", ErrDuplicateObject, pe.Schema, pe.Table, pe.Detail)
		}
	}

	return err
}
