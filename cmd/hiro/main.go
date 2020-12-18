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
	"encoding/json"
	"fmt"
	"os"

	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/apex/log"

	"github.com/urfave/cli/v2"
)

var (
	h   *hiro.Backend
	app = cli.NewApp()
)

func main() {
	app.Name = "hiro"
	app.Usage = "Hiro Platform Toolkit"
	app.Version = "1.0.0"
	app.Action = serverMain

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "log-level",
			Usage:   "set the logging level",
			Value:   "info",
			EnvVars: []string{"LOG_LEVEL"},
		},
		&cli.StringFlag{
			Name:    "db",
			Usage:   "specify the database path",
			EnvVars: []string{"DB_SOURCE"},
		},
		&cli.StringFlag{
			Name:    "server-addr",
			Usage:   "specify the server listen address",
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
		&cli.StringFlag{
			Name:    "env",
			Aliases: []string{"e"},
			Value:   "default",
			EnvVars: []string{"HIRO_ENV"},
		},
	}

	app.Commands = []*cli.Command{
		audienceCommand,
		applicationCommand,
		userCommand,
		roleCommand,
	}

	app.Before = func(c *cli.Context) error {
		var err error

		loadConfig(c)

		h, err = hiro.New(
			hiro.WithDBSource(c.String("db")),
			hiro.Automigrate(),
		)
		if err != nil {
			return err
		}

		if logLevel := c.String("log-level"); logLevel != "" {
			if level, err := log.ParseLevel(logLevel); err == nil {
				log.SetLevel(level)
			}
		}

		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err.Error())
	}
}

func dumpValue(v interface{}) {
	b, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(b))
}
