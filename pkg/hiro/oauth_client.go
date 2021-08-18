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

import "github.com/ModelRocket/hiro/pkg/oauth"

type (
	oauthClient struct {
		*Application
		inst *Instance
	}
)

// ClientID returns the client id
func (c oauthClient) ID() string {
	return *c.Application.ClientID
}

func (c oauthClient) Audience() string {
	return c.inst.Audience
}

func (c oauthClient) Permissions() oauth.Scope {
	rval := make(oauth.Scope, 0)

	for _, p := range c.Application.Permissions {
		rval = append(rval, p.Scope)
	}

	return rval.Unique()
}

// ClientType returns the client type
func (c oauthClient) Type() oauth.ClientType {
	return c.Application.Type
}

// TokenSecret returns the token secret for the client
func (c oauthClient) TokenSecret() oauth.TokenSecret {
	if c.Application.TokenSecret == nil {
		return nil
	}

	if s, err := c.Application.TokenSecret.Key(); err == nil {
		return &oauthSecret{
			Secret: c.Application.TokenSecret,
			key:    s,
		}
	}

	return nil
}

// AuthorizedGrants returns the authorized grants for the client
func (c oauthClient) AuthorizedGrants() oauth.GrantList {
	rval := make(oauth.GrantList, 0)

	for _, g := range c.Application.Grants {
		if g.InstanceID == c.inst.ID {
			rval = append(rval, g.Type)
		}
	}

	return rval
}

func (c oauthClient) ApplicationEndpoints() []string {
	rval := make([]string, 0)

	for _, u := range c.Application.Endpoints {
		if u.InstanceID == c.inst.ID && u.Type == ApplicationEndpointTypeApp {
			rval = append(rval, u.URI)
		}
	}

	return rval
}

func (c oauthClient) RedirectEndpoints() []string {
	rval := make([]string, 0)

	for _, u := range c.Application.Endpoints {
		if u.InstanceID == c.inst.ID && u.Type == ApplicationEndpointTypeRedirect {
			rval = append(rval, u.URI)
		}
	}

	return rval
}
