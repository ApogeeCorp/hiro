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
	"context"
	"fmt"
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
							Value: cli.NewStringSlice(hiro.Permissions...),
						},
						&cli.StringFlag{
							Name:  "token_secret",
							Usage: "Specify a token secret, the default will be to generate a new token of the specifed algorithm",
						},
					},
					Action: audienceCreate,
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

func audienceCreate(c *cli.Context) error {
	var secret oauth.TokenSecret
	var err error

	if s := c.String("token_secret"); s != "" {
		if err := secret.Scan(s); err != nil {
			return err
		}
	} else {
		s, err := oauth.GenerateTokenSecret(oauth.TokenAlgorithm(c.String("token_algorithm")))
		if err != nil {
			return err
		}
		secret = s
	}

	aud, err := h.AudienceCreate(context.Background(), hiro.AudienceCreateInput{
		Name:           c.String("name"),
		TokenLifetime:  time.Duration(c.Duration("token_lifetime")),
		TokenAlgorithm: oauth.TokenAlgorithm(c.String("token_algorithm")),
		TokenSecret:    secret,
		Permissions:    oauth.Permissions(c.StringSlice("permissions")),
	})
	if err != nil {
		return err
	}

	fmt.Printf("Audiece %s [%s] created.\n", aud.Name, aud.ID)

	return err
}
