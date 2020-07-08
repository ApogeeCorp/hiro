//
//  TERALYTIC CONFIDENTIAL
//  _________________
//   2020 TERALYTIC
//   All Rights Reserved.
//
//   NOTICE:  All information contained herein is, and remains
//   the property of TERALYTIC and its suppliers,
//   if any.  The intellectual and technical concepts contained
//   herein are proprietary to TERALYTIC
//   and its suppliers and may be covered by U.S. and Foreign Patents,
//   patents in process, and are protected by trade secret or copyright law.
//   Dissemination of this information or reproduction of this material
//   is strictly forbidden unless prior written permission is obtained
//   from TERALYTIC.
//

// Package teralytic defines the teralytic backend interface
package teralytic

import (
	"errors"

	"github.com/Teralytic/teralytic/api/types"
	"github.com/a8m/rql"
)

var (
	// ErrOptionNotFound should be returned when an option key does not exist
	ErrOptionNotFound = errors.New("option does not exist")

	// ErrObjectExists should be returned create methods when a conflict is encountered
	ErrObjectExists = errors.New("object exists")
)

type (
	// Backend is the teralytic API backend interface. Implementers provide the data persistence to the API server and clients
	Backend interface {
		// OptionCreate will create a new option if it does not exist, existing options should not be updated
		OptionCreate(name string, value interface{}) error

		// OptionUpdate stores a named option in the backend data store, the value should be created if it does not exist
		OptionUpdate(name string, value interface{}) error

		// OptionGet returns a named option from the backend, an error should be returned if the option does not exist
		OptionGet(name string, out interface{}) error

		// OptionRemove removes the named option from the backend, and error should not be returned if the option does not exist
		OptionRemove(name string) error

		// ApplicationCreate creates a new API application from the passed struct.
		// The implementation should set the client id and client secret.
		// On conflict should return ErrObjectExists.
		ApplicationCreate(app *types.Application) error

		// ApplicationGet will return the application matching the filter in the specified query.
		ApplicationGet(query *rql.Query, app *types.Application) error

		// ApplicationUpdate should update an existing application, partial updates should be supported.
		ApplicationUpdate(query *rql.Query, app *types.Application) error

		// UserCreate creates a new user
		UserCreate(user *types.User, password string) error

		// UserGet returns a user for the query
		UserGet(query *rql.Query, user *types.User) error

		// UserUpdate updates a user
		UserUpdate(query *rql.Query, user *types.User) error

		// UserAuthenticate populates a user object of one is found with the login and password
		UserAuthenticate(login, password string, user *types.User) error
	}
)
