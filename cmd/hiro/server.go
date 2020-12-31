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
	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/ModelRocket/sparks/pkg/api"
	"github.com/urfave/cli/v2"
)

var (
	serverCommand = &cli.Command{
		Name:    "server",
		Aliases: []string{"aud"},
		Usage:   "Starts a local hiro server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "db",
				Usage:   "specify the database path",
				EnvVars: []string{"DB_SOURCE"},
			},
			&cli.StringFlag{
				Name:    "server-addr",
				Usage:   "specify the hiro server listen address",
				Value:   "127.0.0.1:9000",
				EnvVars: []string{"SERVER_ADDR"},
			},
			&cli.StringSliceFlag{
				Name:    "cors-allowed-origin",
				Usage:   "Set the cors allowed origin on the http api server",
				Value:   cli.NewStringSlice("*"),
				EnvVars: []string{"CORS_ALLOWED_ORIGIN"},
			},
			&cli.BoolFlag{
				Name:    "http-tracing",
				Usage:   "Enable http tracing",
				EnvVars: []string{"HTTP_TRACE_ENABLE"},
			},
		},
		Action: serverMain,
	}
)

func serverMain(c *cli.Context) error {
	h, err := hiro.New(
		hiro.WithDBSource(c.String("db")),
		hiro.Automigrate(),
		hiro.Initialize(),
	)
	if err != nil {
		return err
	}

	d, err := hiro.NewDaemon(
		hiro.WithServerAddr(c.String("server-addr")),
		hiro.WithController(h),
		hiro.WithAPIOptions(
			api.WithTracing(c.Bool("http-tracing")),
			api.WithCORS(c.StringSlice("cors-allowed-origin")...)),
	)
	if err != nil {
		return err
	}

	return d.Run()
}
