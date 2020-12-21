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
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
)

type (
	// CreatePlatformInput is the params to the initialize method
	CreatePlatformInput struct {
		Name            string             `json:"name"`
		Permissions     oauth.Scope        `json:"permissions"`
		Secret          *oauth.TokenSecret `json:"token_secret,omitempty"`
		SessionLifetime *time.Duration     `json:"session_lifetime,omitempty"`
		AdminUser       string             `json:"admin"`
		Update          bool               `json:"update"`
	}
)

// CreatePlatform will create an audience, application, role, and user with that role
// If the user exists, it will be granted that role
func (b *Backend) CreatePlatform(ctx context.Context, params CreatePlatformInput) error {
	// check if the audience exits
	aud, err := b.AudienceGet(ctx, AudienceGetInput{
		Name: ptr.String(params.Name),
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if aud == nil {
		if params.Secret == nil {
			// generate a new token
			secret, err := oauth.GenerateTokenSecret(oauth.TokenAlgorithmRS256, time.Hour)
			if err != nil {
				return err
			}
			params.Secret = secret
		}

		if params.SessionLifetime == nil {
			params.SessionLifetime = ptr.Duration(time.Hour * 24 * 30)
		}

		aud, err = b.AudienceCreate(ctx, AudienceCreateInput{
			Name:            params.Name,
			TokenSecret:     params.Secret,
			SessionLifetime: time.Hour * 24 * 30,
			Permissions:     append(Scopes, oauth.Scopes...),
		})
		if err != nil {
			return err
		}
	} else if params.Update {
		aud, err = b.AudienceUpdate(ctx, AudienceUpdateInput{
			AudienceID:  aud.ID,
			Permissions: append(Scopes, oauth.Scopes...),
		})
		if err != nil {
			return err
		}
	}

	return nil
}
