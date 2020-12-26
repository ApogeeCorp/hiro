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

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "log-level",
			Usage:   "set the logging level",
			Value:   "info",
			EnvVars: []string{"LOG_LEVEL"},
		},
		&cli.StringFlag{
			Name:    "api-host",
			Usage:   "specify the hiro server host",
			Value:   "http://127.0.0.1:9000",
			EnvVars: []string{"API_HOST"},
		},
		&cli.BoolFlag{
			Name:    "rpc-no-tls",
			Value:   false,
			EnvVars: []string{"RPC_NO_TLS"},
		},
		&cli.StringFlag{
			Name:    "audience",
			Usage:   "the hiro audience",
			Value:   "hiro",
			EnvVars: []string{"HIRO_AUDIENCE"},
		},
		&cli.StringFlag{
			Name:    "client-id",
			Usage:   "the hiro application client id",
			EnvVars: []string{"CLIENT_ID"},
		},
		&cli.StringFlag{
			Name:    "client-secret",
			Usage:   "the hiro application client secret",
			EnvVars: []string{"CLIENT_SECRET"},
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
		loadConfig(c)

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
