/*
 * This file is part of the Atomic Stack (https://github.com/libatomic/atomic).
 * Copyright (c) 2020 Atomic Publishing.
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
	"os"

	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/ModelRocket/hiro/pkg/types"
	"github.com/apex/log"

	"github.com/urfave/cli/v2"
)

var (
	app = cli.NewApp()
)

func main() {
	app.Name = "hiro"
	app.Usage = "Hiro Tool"
	app.Version = "1.0.0"

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
			Name:    "aud",
			Usage:   "specify the hiro audience to use",
			EnvVars: []string{"HIRO_AUDIENCE"},
		},
	}

	app.Commands = []*cli.Command{
		{
			Name:   "init",
			Usage:  "Initialize a hiro instance",
			Action: initialize,
		},
	}

	app.Before = func(c *cli.Context) error {
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

func initialize(c *cli.Context) error {
	_, err := hiro.New(
		hiro.WithDBSource(c.String("db")),
		hiro.Automigrate(),
		hiro.Initialize(),
		hiro.WithAudience(types.ID(c.String("aud"))),
	)

	return err
}
