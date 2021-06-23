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
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/ModelRocket/hiro/pkg/hiro/pb"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/dustin/go-humanize"
	"github.com/lensesio/tableprinter"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v2"
)

var (
	audienceCreateFlags = []cli.Flag{
		&cli.StringFlag{
			Name:     "name",
			Usage:    "The audience name",
			Required: true,
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
			Usage: "Specify the oauth token algorithm (rsa,hmac)",
			Value: "rsa",
		},
		&cli.StringSliceFlag{
			Name:  "permissions",
			Usage: "Specifiy the audience permissions",
		},
		&cli.DurationFlag{
			Name:  "session_lifetime",
			Usage: "Specify the audience browser session lifetime",
		},
		&cli.PathFlag{
			Name:      "token_file",
			Usage:     "Read the token from the file",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:  "token",
			Usage: "Specify the token as a base64 string",
		},
	}

	audienceUpdateFlags = []cli.Flag{
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
			Usage: "Specify the oauth token algorithm (rsa,hmac)",
			Value: "rsa",
		},
		&cli.StringSliceFlag{
			Name:  "permissions",
			Usage: "Specifiy the audience permissions",
		},
		&cli.DurationFlag{
			Name:  "session_lifetime",
			Usage: "Specify the audience browser session lifetime",
		},
	}

	audienceCommand = &cli.Command{
		Name:    "audience",
		Aliases: []string{"aud"},
		Usage:   "Instance management",
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
				Flags:  audienceUpdateFlags,
				Action: audienceUpdate,
			},
		},
	}
)

func audienceCreate(c *cli.Context) error {
	var err error
	var aud hiro.Instance

	conn, err := rpcClient(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	h := pb.NewHiroClient(conn)

	lifetime := time.Duration(c.Duration("token_lifetime"))
	if lifetime == 0 {
		lifetime = time.Hour
	}

	sessionLifetime := c.Duration("session-lifetime")
	if sessionLifetime == 0 {
		sessionLifetime = time.Hour * 24 * 30
	}

	perms := c.StringSlice("permissions")
	if len(perms) == 0 {
		perms = append(hiro.Scopes, oauth.Scopes...)
	}

	var algo pb.Secret_TokenAlgorithm

	switch c.String("token_algorithm") {
	case "rsa":
		algo = pb.Secret_RS256
	case "hmac":
		algo = pb.Secret_HS256
	default:
		return errors.New("invalid token_algorithm")
	}

	a, err := h.InstanceCreate(context.Background(), &pb.InstanceCreateRequest{
		Name:            c.String("name"),
		Description:     ptr.NilString(c.String("description")),
		TokenLifetime:   uint64(lifetime.Seconds()),
		TokenAlgorithm:  algo,
		Permissions:     oauth.Scope(perms),
		SessionLifetime: uint64(sessionLifetime.Seconds()),
	})
	if err != nil {
		if errors.Is(err, hiro.ErrDuplicateObject) {
			fmt.Printf("Instance with name %s already exists\n", c.String("name"))
			return nil
		}
		return err
	}

	if m := c.String("token_hmac"); m != "" {
		_, err = h.SecretCreate(context.Background(), &pb.SecretCreateRequest{
			InstanceId: a.Id,
			Type:       pb.Secret_Token,
			Algorithm:  pb.Secret_HS256,
			Key:        &m,
		})
	} else if r := c.Path("token_rsa"); r != "" {
		data, err := ioutil.ReadFile(r)
		if err != nil {
			return err
		}

		key := base64.RawURLEncoding.EncodeToString(data)

		_, err = h.SecretCreate(context.Background(), &pb.SecretCreateRequest{
			InstanceId: a.Id,
			Type:       pb.Secret_Token,
			Algorithm:  pb.Secret_RS256,
			Key:        &key,
		})
	} else {
		_, err = h.SecretCreate(context.Background(), &pb.SecretCreateRequest{
			InstanceId: a.Id,
			Type:       pb.Secret_Token,
			Algorithm:  a.TokenAlgorithm,
		})
	}

	// generate a new session secret
	_, err = h.SecretCreate(context.Background(), &pb.SecretCreateRequest{
		InstanceId: a.Id,
		Type:       pb.Secret_Session,
	})
	if err != nil {
		return err
	}

	aud.FromProto(a)

	fmt.Printf("Audiece %s [%s] created.\n", aud.Name, aud.ID)

	dumpValue(aud)

	return err
}

func audienceGet(c *cli.Context) error {
	var aud hiro.Instance

	conn, err := rpcClient(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	h := pb.NewHiroClient(conn)

	req := &pb.InstanceGetRequest{}

	if id := c.String("id"); id != "" {
		req.GetBy = &pb.InstanceGetRequest_Id{
			Id: id,
		}
	} else if name := c.String("name"); name != "" {
		req.GetBy = &pb.InstanceGetRequest_Name{
			Name: name,
		}
	}

	rval, err := h.InstanceGet(context.Background(), req)
	if err != nil {
		return err
	}

	aud.FromProto(rval)

	dumpValue(aud)

	return nil
}

func audienceDelete(c *cli.Context) error {
	id := c.String("id")

	prompt := promptui.Prompt{
		Label:     fmt.Sprintf("Delete Instance %s", id),
		IsConfirm: true,
	}

	result, err := prompt.Run()
	if err != nil && err != promptui.ErrAbort {
		return err
	}

	if result == "y" {
		conn, err := rpcClient(c)
		if err != nil {
			return err
		}
		defer conn.Close()

		h := pb.NewHiroClient(conn)

		if _, err := h.InstanceDelete(context.Background(), &pb.InstanceDeleteRequest{
			Id: id,
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
	type entry struct {
		ID          hiro.ID `header:"id"`
		Name        string  `header:"name"`
		Description *string `header:"description"`
		CreatedAt   string  `header:"created_at"`
	}

	conn, err := rpcClient(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	h := pb.NewHiroClient(conn)

	auds, err := h.InstanceList(context.Background(), &pb.InstanceListRequest{})
	if err != nil {
		return err
	}

	list := make([]entry, 0)

	for {
		a, err := auds.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		list = append(list, entry{
			ID:          hiro.ID(a.Id),
			Name:        a.Name,
			Description: a.Description,
			CreatedAt:   humanize.Time(a.CreatedAt.AsTime()),
		})
	}

	tableprinter.Print(os.Stdout, list)

	fmt.Println()

	return nil
}

func audienceUpdate(c *cli.Context) error {
	var err error

	conn, err := rpcClient(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	h := pb.NewHiroClient(conn)

	params := pb.InstanceUpdateRequest{
		Id: c.String("id"),
	}

	lifetime := uint64(c.Duration("token_lifetime").Seconds())
	if lifetime > 0 {
		params.TokenLifetime = &lifetime
	}

	sessionLifetime := uint64(c.Duration("session_lifetime").Seconds())
	if sessionLifetime > 0 {
		params.SessionLifetime = &sessionLifetime
	}

	if name := c.String("name"); name != "" {
		params.Name = &name
	}

	if desc := c.String("description"); desc != "" {
		params.Description = &desc
	}

	if perms := c.StringSlice("permissions"); len(perms) > 0 {
		params.Permissions = &pb.InstanceUpdateRequest_PermissionsUpdate{
			Add: oauth.Scope(perms),
		}
	}

	aud, err := h.InstanceUpdate(context.Background(), &params)
	if err != nil {
		return err
	}

	fmt.Printf("Audiece %s [%s] updated.\n", aud.Name, aud.Id)

	dumpValue(aud)

	return err
}
