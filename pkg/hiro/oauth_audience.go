/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://githuh.com/ModelRocket/hiro
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

	"github.com/ModelRocket/hiro/pkg/oauth"
)

type (
	oauthAudience struct {
		*Instance
	}
)

func (a oauthAudience) ID() string {
	return a.Audience
}

func (a oauthAudience) Secrets() []oauth.TokenSecret {
	rval := make([]oauth.TokenSecret, 0)
	for _, s := range a.Instance.Secrets {
		if s.Type != SecretTypeToken {
			continue
		}

		if *s.Algorithm == oauth.TokenAlgorithmRS256 {
			if k, err := s.Key(); err == nil {
				rval = append(rval, &oauthSecret{
					Secret: &s,
					key:    k,
				})
			}
		}
	}

	return rval
}

func (a oauthAudience) Permissions() oauth.Scope {
	rval := make(oauth.Scope, 0)

	for _, p := range a.Instance.Permissions {
		rval = append(rval, p.Scope)
	}

	return rval
}

func (a oauthAudience) RefreshTokenLifetime() time.Duration {
	return a.SessionLifetime
}
