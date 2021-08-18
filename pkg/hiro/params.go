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
	"time"

	"github.com/ModelRocket/hiro/pkg/common"
)

type (
	// Params contains common components for library methods
	Params struct {
		Expand   common.StringSlice `json:"expand,omitempty"`
		Metadata common.Map         `json:"metadata,omitempty"`
		DB       DB                 `json:"-"`
	}

	// ListParams contains common components for list type methods
	ListParams struct {
		Expand []string   `json:"expand,omitempty"`
		Limit  *int64     `json:"limit,omitempty"`
		Offset *int64     `json:"offset,omitempty"`
		After  *time.Time `json:"after"`
		Before *time.Time `json:"before"`
		DB     DB         `json:"-"`
	}

	Expand common.StringSlice
)

// AddExpand appends values to the expand
func (p *Params) AddExpand(e ...string) *Params {
	p.Expand = common.StringSlice(append(p.Expand, e...)).Unique()
	return p
}

// AddExpand appends values to the expand
func (p *ListParams) AddExpand(e ...string) *ListParams {
	p.Expand = common.StringSlice(append(p.Expand, e...)).Unique()
	return p
}
