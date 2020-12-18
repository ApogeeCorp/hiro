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

package oauth

import (
	"encoding/json"
	"time"
)

type (

	// Time is a time structure used for tokens
	Time time.Time
)

// MarshalJSON markshals the time to an epoch
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).UTC().Unix())
}

// Time casts the oauth time back to a time.Time
func (t Time) Time() time.Time {
	return time.Time(t)
}

// Ptr returns a pointer to this time
func (t Time) Ptr() *Time {
	return &t
}
