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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/ModelRocket/hiro/pkg/types"
	"github.com/dustin/go-humanize"
	"github.com/lensesio/tableprinter"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v2"
)

var (
	audienceCreateFlags = []cli.Flag{
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
			Value: string(oauth.TokenAlgorithmRS256),
		},
		&cli.StringSliceFlag{
			Name:  "permissions",
			Usage: "Specifiy the audience permissions",
		},
		&cli.DurationFlag{
			Name:  "session_lifetime",
			Usage: "Specify the audience browser session lifetime",
			Value: time.Hour * 24 * 30,
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
	}

	audienceCommand = &cli.Command{
		Name:    "audience",
		Aliases: []string{"aud"},
		Usage:   "Audience management",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "id",
				Usage: "The audience id for querying by id",
			},
			&cli.StringFlag{
				Name:  "name",
				Usage: "The audience name for querying by",
			},
		},
		Subcommands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create a new audience",
				Flags:  audienceCreateFlags,
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
				Name:   "update",
				Usage:  "Update and existing audience",
				Flags:  audienceCreateFlags,
				Action: audienceUpdate,
			},
		},
	}
)

func audienceCreate(c *cli.Context) error {
	var secret *oauth.TokenSecret
	var err error

	lifetime := time.Duration(c.Duration("token_lifetime"))
	if lifetime == 0 {
		lifetime = time.Hour
	}

	sessionLifetime := c.Duration("session-lifetime")
	if sessionLifetime == 0 {
		sessionLifetime = time.Hour * 24 * 30
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

	perms := c.StringSlice("permissions")
	if len(perms) == 0 {
		perms = append(hiro.Scopes, oauth.Scopes...)
	}

	aud, err := h.AudienceCreate(context.Background(), hiro.AudienceCreateInput{
		Name:            c.String("name"),
		Description:     ptr.NilString(c.String("description")),
		TokenSecret:     secret,
		Permissions:     oauth.Scope(perms),
		SessionLifetime: sessionLifetime,
	})
	if err != nil {
		if errors.Is(err, hiro.ErrDuplicateObject) {
			fmt.Printf("Audience with name %s already exists\n", c.String("name"))
			return nil
		}
		return err
	}

	fmt.Printf("Audiece %s [%s] created.\n", aud.Name, aud.ID)

	dumpValue(aud)

	return err
}

func audienceGet(c *cli.Context) error {
	var params hiro.AudienceGetInput

	if id := types.ID(c.String("id")); id.Valid() {
		params.AudienceID = &id
	} else if name := c.String("name"); name != "" {
		params.Name = &name
	}

	aud, err := h.AudienceGet(context.Background(), params)
	if err != nil {
		return err
	}

	dumpValue(aud)

	return nil
}

func audienceDelete(c *cli.Context) error {
	id := types.ID(c.String("id"))

	prompt := promptui.Prompt{
		Label:     fmt.Sprintf("Delete Audience %s", id.String()),
		IsConfirm: true,
	}

	result, err := prompt.Run()
	if err != nil && err != promptui.ErrAbort {
		return err
	}

	if result == "y" {
		if err := h.AudienceDelete(context.Background(), hiro.AudienceDeleteInput{
			AudienceID: id,
		}); err != nil {
			return err
		}

		fmt.Println("audience deleted")
		fmt.Println()
	} else {
		fmt.Println("operation cancelled")
	}

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
			Description: safe.String(a.Description),
			CreatedAt:   humanize.Time(a.CreatedAt),
		})
	}
	tableprinter.Print(os.Stdout, list)
	fmt.Println()

	return nil
}

func audienceUpdate(c *cli.Context) error {
	var secret *oauth.TokenSecret
	var err error

	params := hiro.AudienceUpdateInput{
		AudienceID: types.ID(c.String("id")),
	}

	lifetime := c.Duration("token_lifetime")
	if lifetime > 0 {
		secret = &oauth.TokenSecret{
			Lifetime: lifetime,
		}
	}

	sessionLifetime := c.Duration("session_lifetime")
	if sessionLifetime > 0 {
		params.SessionLifetime = &sessionLifetime
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
