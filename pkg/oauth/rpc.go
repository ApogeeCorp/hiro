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
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

type (
	oauthCreds struct {
		token  *oauth2.Token
		secure bool
	}
)

// ClientCredentials returns the ClientCredentials for the hiro
func ClientCredentials(config clientcredentials.Config, secure bool) (credentials.PerRPCCredentials, error) {
	token, err := config.Token(oauth2.NoContext)
	if err != nil {
		return nil, err
	}

	if secure {
		// for secure requests, we use the proper interface
		return oauth.NewOauthAccess(token), nil
	}

	// this implementation allows for oauth over local insecure connections
	return oauthCreds{
		token:  token,
		secure: secure,
	}, nil
}

func (oa oauthCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": oa.token.Type() + " " + oa.token.AccessToken,
	}, nil
}

func (oa oauthCreds) RequireTransportSecurity() bool {
	return oa.secure
}
