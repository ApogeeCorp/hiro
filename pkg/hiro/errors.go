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

	"github.com/lib/pq"
)

var (
	// ErrDuplicateObject is returned where there is unique constraint violation
	ErrDuplicateObject = errors.New("duplicate object")

	// ErrInputValidation is returned when a object validation fails
	ErrInputValidation = errors.New("request validation")

	// ErrNotFound is returned when an object is not found
	ErrNotFound = errors.New("not found")

	// ErrAuthFailed is returned when user authentication fails to due to password mistmatch
	ErrAuthFailed = errors.New("authentication failed")

	// ErrDatabaseTimeout is returned when the database cannot be reached
	ErrDatabaseTimeout = errors.New("database connection timeout")

	// ErrContextNotFound is returned when hiro is not in the context
	ErrContextNotFound = errors.New("hiro not found in context")
)

// parseSQLError provides cleaner errors for database issues
func parseSQLError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %s", ErrNotFound, err)
	}

	if pe, ok := err.(*pq.Error); ok {
		switch pe.Code.Name() {
		case "unique_violation":
			return fmt.Errorf("%w [%s.%s]: %s", ErrDuplicateObject, pe.Schema, pe.Table, pe.Detail)
		}
	}

	return err
}
