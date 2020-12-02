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
