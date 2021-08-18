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
	"fmt"

	"github.com/ModelRocket/hiro/api/swagger"
	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/urfave/cli/v2"
)

var (
	serverCommand = &cli.Command{
		Name:  "server",
		Usage: "Starts a local hiro server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "db",
				Usage:    "Specify the database path",
				EnvVars:  []string{"DB_SOURCE"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "server-addr",
				Usage:   "Specify the hiro server listen address",
				Value:   "0.0.0.0:9000",
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
			&cli.BoolFlag{
				Name:  "auto-migrate",
				Usage: "Auto-Migrate the database to the latest version",
			},
		},
		Subcommands: []*cli.Command{
			{
				Name:    "initialize",
				Aliases: []string{"init"},
				Usage:   "initialize the server",
				Action:  serverInitialize,
			},
		},
		Before: func(c *cli.Context) error {
			var err error

			opts := []hiro.HiroOption{
				hiro.WithDBSource(c.String("db")),
			}

			if c.Bool("auto-migrate") {
				opts = append(opts, hiro.Automigrate())
			}

			h, err = hiro.New(opts...)
			if err != nil {
				return err
			}

			return nil
		},
		Action: serverMain,
	}
)

func serverMain(c *cli.Context) error {
	s, err := hiro.NewService(
		hiro.WithServerAddr(c.String("server-addr")),
		hiro.WithController(h),
		hiro.WithAPIOptions(
			api.WithTracing(c.Bool("http-tracing")),
			api.WithCORS(c.StringSlice("cors-allowed-origin")...)),
	)
	if err != nil {
		return fmt.Errorf("failed to start hiro service: %w", err)
	}

	return s.Run()
}

func serverInitialize(c *cli.Context) error {
	_, err := h.APIImport(c.Context, hiro.APIImportParams{
		Spec: string(swagger.HiroSwaggerSpec),
	})
	if err != nil {
		return fmt.Errorf("failed to create hiro api: %w", err)
	}

	return nil
}
