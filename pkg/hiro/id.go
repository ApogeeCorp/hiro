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
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/mr-tron/base58/base58"
	"github.com/spf13/cast"
)

type (
	// ID is the hiro uuid implementation wrapper that
	// base58 encodes/decodes the values as text or json
	ID string
)

// NewID will parse or generate a value to make a new ID
func NewID(id ...interface{}) ID {
	if len(id) > 0 {
		switch t := id[0].(type) {
		case ID:
			return t

		case *ID:
			if t != nil {
				return *t
			}

		case nil:
			return ID("")

		default:
			return ID(cast.ToString(t))
		}
	}

	u := uuid.Must(uuid.NewRandom())

	return ID(base58.Encode(u[:]))
}

// Valid returns true if the id is valid
func (id ID) Valid() bool {
	// empty ids are not considered valid
	if id == "" {
		return false
	}
	if err := id.Validate(); err != nil {
		return false
	}

	return true
}

// Validate validates the id as a uuid
func (id ID) Validate() error {
	// empty ids should be validated because they could be coming from the db some other marshalling
	if id == "" {
		return nil
	}

	data, err := base58.Decode(string(id))
	if err != nil {
		return err
	}

	if _, err := uuid.FromBytes(data); err != nil {
		return err
	}

	return nil
}

// MarshalJSON handles json marshaling of this type
func (id ID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

// Hex encodes the id as hex
func (id ID) Hex() string {
	b, _ := base58.Decode(id.String())
	return hex.EncodeToString(b)
}

// UnmarshalJSON handles the unmarshaling of this type
func (id *ID) UnmarshalJSON(b []byte) error {
	if b == nil {
		return nil
	}

	*id = ID(b)

	return id.Validate()
}

func (id ID) String() string {
	return string(id)
}

// Scan implements the Scanner interface.
func (id *ID) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	switch s := value.(type) {
	case string:
		u, err := uuid.Parse(s)
		if err != nil {
			return err
		}
		*id = ID(base58.Encode(u[:]))

	case []byte:
		u, err := uuid.ParseBytes(s)
		if err != nil {
			return err
		}
		*id = ID(base58.Encode(u[:]))

	case nil:

	default:
		return errors.New("unexpected type for ID")
	}

	return nil
}

// Value implements the driver Valuer interface.
func (id ID) Value() (driver.Value, error) {
	if !id.Valid() {
		return nil, nil
	}

	data, err := base58.Decode(string(id))
	if err != nil {
		return nil, err
	}

	u, err := uuid.FromBytes(data)
	if err != nil {
		return nil, err
	}

	return u.Value()
}
