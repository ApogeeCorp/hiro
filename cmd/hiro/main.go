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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/types"
	"github.com/apex/log"
	"github.com/lensesio/tableprinter"

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
					Name:   "list",
					Usage:  "List all audiences",
					Action: audienceList,
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

func audienceCreate(c *cli.Context) error {
	var secret *oauth.Token
	var err error

	lifetime := time.Duration(c.Duration("token_lifetime"))

	if h := c.String("token_hmac"); h != "" {
		secret, err = oauth.NewTokenSecret(oauth.TokenAlgorithmHS256, []byte(h), lifetime)
		if err != nil {
			return err
		}
	} else if h := c.Path("token_rsa"); h != "" {
		data, err := ioutil.ReadFile(h)
		if err != nil {
			return err
		}

		secret, err = oauth.NewTokenSecret(oauth.TokenAlgorithmRS256, data, lifetime)
		if err != nil {
			return err
		}
	} else {
		s, err := oauth.GenerateTokenSecret(
			oauth.TokenAlgorithm(c.String("token_algorithm")),
			lifetime,
		)
		if err != nil {
			return err
		}
		secret = s
	}

	aud, err := h.AudienceCreate(context.Background(), hiro.AudienceCreateInput{
		Name:        c.String("name"),
		Description: ptr.NilString(c.String("description")),
		TokenSecret: secret,
		Permissions: oauth.Scope(c.StringSlice("permissions")),
	})
	if err != nil {
		return err
	}

	fmt.Printf("Audiece %s [%s] created.\n", aud.Name, aud.ID)

	dumpValue(aud)

	return err
}

func audienceGet(c *cli.Context) error {
	id := types.ID(c.String("id"))

	aud, err := h.AudienceGet(context.Background(), hiro.AudienceGetInput{
		AudienceID: &id,
	})
	if err != nil {
		return err
	}

	dumpValue(aud)

	return nil
}

func audienceList(c *cli.Context) error {
	auds, err := h.AudienceList(context.Background(), hiro.AudienceListInput{})
	if err != nil {
		return err
	}

	fmt.Printf("Found %d audience(s)\n\n", len(auds))

	type entry struct {
		ID          types.ID `header:"id"`
		Name        string   `header:"name"`
		Description string   `header:"description"`
		CreatedAt   string   `header:"created_at"`
	}

	list := make([]entry, 0)
	for _, a := range auds {
		list = append(list, entry{
			ID:          a.ID,
			Name:        a.Name,
			Description: ptr.SafeString(a.Description),
			CreatedAt:   a.CreatedAt.Format(time.RFC3339),
		})
	}
	tableprinter.Print(os.Stdout, list)
	fmt.Println()

	return nil
}

func audienceUpdate(c *cli.Context) error {
	var secret *oauth.Token
	var err error

	params := hiro.AudienceUpdateInput{
		AudienceID: types.ID(c.String("id")),
	}

	lifetime := time.Duration(c.Duration("token_lifetime"))
	if lifetime > 0 {
		secret = &oauth.Token{
			Lifetime: lifetime,
		}
	}

	if h := c.String("token_hmac"); h != "" {
		secret, err = oauth.NewTokenSecret(oauth.TokenAlgorithmHS256, []byte(h), lifetime)
		if err != nil {
			return err
		}
	} else if h := c.Path("token_rsa"); h != "" {
		data, err := ioutil.ReadFile(h)
		if err != nil {
			return err
		}

		secret, err = oauth.NewTokenSecret(oauth.TokenAlgorithmRS256, data, lifetime)
		if err != nil {
			return err
		}
	}
	params.TokenSecret = secret

	if name := c.String("name"); name != "" {
		params.Name = &name
	}

	if desc := c.String("description"); desc != "" {
		params.Description = &desc
	}

	if perms := c.StringSlice("permissions"); len(perms) > 0 {
		params.Permissions = oauth.Scope(perms)
	}

	aud, err := h.AudienceUpdate(context.Background(), params)
	if err != nil {
		return err
	}

	fmt.Printf("Audiece %s [%s] updated.\n", aud.Name, aud.ID)

	dumpValue(aud)

	return err
}

func dumpValue(v interface{}) {
	b, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(b))
}
