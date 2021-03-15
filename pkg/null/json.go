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

package null

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/jmoiron/sqlx/types"
)

// JSON safely convers or marshals to a sql.NullJSONText
// Failure to marshal results in an error object
func JSON(j interface{}) types.NullJSONText {
	switch t := j.(type) {
	case []byte:
		return types.NullJSONText{Valid: true, JSONText: t}
	case string:
		return types.NullJSONText{Valid: true, JSONText: []byte(t)}
	case *string:
		if t == nil {
			return types.NullJSONText{Valid: false}
		}
		return types.NullJSONText{Valid: true, JSONText: []byte(*t)}
	}

	val := reflect.ValueOf(j)
	if val.Kind() == reflect.Ptr && val.IsNil() {
		return types.NullJSONText{Valid: false}
	}
	if val.Kind() == reflect.Map && val.Len() == 0 {
		return types.NullJSONText{Valid: false}
	}
	if val.Kind() == reflect.Array && val.Len() == 0 {
		return types.NullJSONText{Valid: false}
	}

	data, err := json.Marshal(j)
	if err != nil {
		data = []byte(fmt.Sprintf(`
		{
			"error": "%s"
		}
		`, err.Error()))
	}

	return types.NullJSONText{Valid: true, JSONText: data}
}
