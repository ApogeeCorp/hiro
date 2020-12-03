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
	"time"

	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/apex/log"

	"github.com/urfave/cli/v2"
)

var (
	h   *hiro.Hiro
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
	}

	app.Commands = []*cli.Command{
		{
			Name:    "audience",
			Aliases: []string{"aud"},
			Usage:   "Audience management",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "id",
					Usage: "The audience id for commands that require it",
				},
			},
			Subcommands: []*cli.Command{
				{
					Name:  "create",
					Usage: "Create a new audience",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:  "name",
							Usage: "The audience name",
							Value: "hiro",
						},
						&cli.StringFlag{
							Name:  "description",
							Usage: "The audience description",
							Value: "The default hiro audience",
						},
						&cli.DurationFlag{
							Name:  "token_lifetime",
							Usage: "The oauth token lifetime in seconds for the audience",
							Value: time.Minute * 60,
						},
						&cli.StringFlag{
							Name:  "token_algorithm",
							Usage: "Specify the oauth token algorithm",
							Value: string(oauth.TokenAlgorithmRS256),
						},
						&cli.StringSliceFlag{
							Name:  "permissions",
							Usage: "Specifiy the audience permissions",
							Value: cli.NewStringSlice(append(oauth.Scopes, hiro.Scopes...)...),
						},
						&cli.PathFlag{
							Name:      "token_rsa",
							Usage:     "Specify an rsa token as a pem file",
							TakesFile: true,
						},
						&cli.StringFlag{
							Name:  "token_hmac",
							Usage: "Specify an hmac key as a string",
						},
					},
					Action: audienceCreate,
				},
				{
					Name:   "get",
					Usage:  "Get an audience by id",
					Action: audienceGet,
				},
				{
					Name:    "list",
					Aliases: []string{"ls"},
					Usage:   "List all audiences",
					Action:  audienceList,
				},
				{
					Name:    "delete",
					Aliases: []string{"rm"},
					Usage:   "Delete an audience by id",
					Action:  audienceDelete,
				},
				{
					Name:  "update",
					Usage: "Update and existing audience",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:  "name",
							Usage: "The audience name",
						},
						&cli.StringFlag{
							Name:  "description",
							Usage: "The audience description",
						},
						&cli.DurationFlag{
							Name:  "token_lifetime",
							Usage: "The oauth token lifetime in seconds for the audience",
						},
						&cli.StringFlag{
							Name:  "token_algorithm",
							Usage: "Specify the oauth token algorithm",
						},
						&cli.StringSliceFlag{
							Name:  "permissions",
							Usage: "Specifiy the audience permissions",
						},
						&cli.PathFlag{
							Name:      "token_rsa",
							Usage:     "Specify an rsa token as a pem file",
							TakesFile: true,
						},
						&cli.StringFlag{
							Name:  "token_hmac",
							Usage: "Specify an hmac key as a string",
						},
					},
					Action: audienceUpdate,
				},
			},
		},
	}

	app.Before = func(c *cli.Context) error {
		var err error

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
