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

package main

import (
	"crypto/tls"
	"fmt"
	"net/url"

	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/johnsiilver/getcert"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func rpcClient(c *cli.Context) (*grpc.ClientConn, error) {
	var conn *grpc.ClientConn

	u, err := url.Parse(c.String("api-host"))
	if err != nil {
		return nil, err
	}

	creds, err := oauth.ClientCredentials(clientcredentials.Config{
		TokenURL:       fmt.Sprintf("%s/oauth/token", u.String()),
		EndpointParams: url.Values{"audience": []string{c.String("audience")}},
		ClientID:       c.String("client-id"),
		ClientSecret:   c.String("client-secret"),
		AuthStyle:      oauth2.AuthStyleInParams,
		Scopes:         []string{},
	}, !c.Bool("rpc-no-tls"))
	if err != nil {
		return nil, err
	}

	port := u.Port()
	if port == "" {
		port = "443"
	}

	if !c.Bool("rpc-no-tls") {
		tlsCert, _, err := getcert.FromTLSServer(u.Hostname()+":"+port, true)
		if err != nil {
			return nil, err
		}

		conn, err = grpc.Dial(
			u.Host+":"+port,
			grpc.WithTransportCredentials(
				credentials.NewTLS(
					&tls.Config{
						ServerName:         u.Host,
						Certificates:       []tls.Certificate{tlsCert},
						ClientAuth:         tls.NoClientCert,
						InsecureSkipVerify: true,
					})),
			grpc.WithPerRPCCredentials(creds))
	} else {
		conn, err = grpc.Dial(
			u.Host,
			grpc.WithInsecure(),
			grpc.WithPerRPCCredentials(creds),
		)
	}
	if err != nil {
		return nil, err
	}

	return conn, nil
}
