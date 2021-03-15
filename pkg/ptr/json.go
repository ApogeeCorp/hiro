/*************************************************************************
 * MIT License
 * Copyright (c) 2019 Model Rocket
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

package ptr

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// JSON is json pointer
type JSON struct {
	json.RawMessage
	valid bool
}

// MarshalJSON marshals the object to json
func (j JSON) MarshalJSON() ([]byte, error) {
	if j.valid == false {
		return []byte("{}"), nil
	}
	return json.Marshal(j.RawMessage)
}

// Value returns Map as a value that can be stored as json in the database
func (j JSON) Value() (driver.Value, error) {
	if j.valid == false {
		return nil, nil
	}

	return json.Marshal(j.RawMessage)
}

// Scan reads a json value from the database into a Map
func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &j.RawMessage); err != nil {
		return err
	}

	j.valid = true

	return nil
}
