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
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/dustin/go-humanize"
	"github.com/lensesio/tableprinter"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v2"
)

var (
	instanceCreateFlags = []cli.Flag{
		&cli.StringFlag{
			Name:     "name",
			Usage:    "The instance name",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "description",
			Usage: "The instance description",
		},
		&cli.StringFlag{
			Name:     "audience",
			Usage:    "The instance audience domain",
			Required: true,
		},
		&cli.DurationFlag{
			Name:  "token-lifetime",
			Usage: "The oauth token lifetime in seconds for the instance",
			Value: hiro.DefaultTokenLifetime,
		},
		&cli.StringFlag{
			Name:  "token-algorithm",
			Usage: "Specify the oauth token algorithm (rsa,hmac)",
			Value: "rsa",
		},
		&cli.DurationFlag{
			Name:  "session-lifetime",
			Usage: "Specify the instance browser session lifetime in seconds",
			Value: hiro.DefaultSessionLifetime,
		},
		&cli.DurationFlag{
			Name:  "refresh-token-lifetime",
			Usage: "Specify the refresh token lifetime in seconds",
			Value: hiro.DefaultRefreshTokenLifetime,
		},
		&cli.DurationFlag{
			Name:  "login-token-lifetime",
			Usage: "Specify the login token lifetime in seconds",
			Value: hiro.DefaultLoginTokenLifetime,
		},
		&cli.DurationFlag{
			Name:  "invite-token-lifetime",
			Usage: "Specify the invite token lifetime in seconds",
			Value: hiro.DefaultInviteTokenLifetime,
		},
		&cli.DurationFlag{
			Name:  "verify-token-lifetime",
			Usage: "Specify the verify token lifetime in seconds",
			Value: hiro.DefaultVerifyTokenLifetime,
		},
		&cli.DurationFlag{
			Name:  "auth-code-lifetime",
			Usage: "Specify the authorization code lifetime in seconds",
			Value: hiro.DefaultAuthCodeLifetime,
		},
		&cli.StringSliceFlag{
			Name:  "permissions",
			Usage: "Specifiy the instance permissions",
		},
		&cli.PathFlag{
			Name:      "token-file",
			Usage:     "Read the token from the file",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:  "token",
			Usage: "Specify the token as a base64 string",
		},
	}

	instanceUpdateFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Usage: "The instance name",
		},
		&cli.StringFlag{
			Name:  "description",
			Usage: "The instance description",
		},
		&cli.DurationFlag{
			Name:  "token_lifetime",
			Usage: "The oauth token lifetime in seconds for the instance",
		},
		&cli.StringFlag{
			Name:  "token_algorithm",
			Usage: "Specify the oauth token algorithm (rsa,hmac)",
			Value: "rsa",
		},
		&cli.StringSliceFlag{
			Name:  "add-permission",
			Usage: "Add an instance permission",
		},
		&cli.StringSliceFlag{
			Name:  "rem-permission",
			Usage: "Remove an instance permission",
		},
		&cli.DurationFlag{
			Name:  "session_lifetime",
			Usage: "Specify the instance browser session lifetime",
		},
	}

	instanceCommand = &cli.Command{
		Name:    "instance",
		Aliases: []string{"inst"},
		Usage:   "Instance management",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "id",
				Usage: "The instance id",
			},
			&cli.StringFlag{
				Name:  "audience",
				Usage: "The instance audience",
			},
		},
		Subcommands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create a new instance",
				Flags:  instanceCreateFlags,
				Action: instanceCreate,
			},
			{
				Name:   "get",
				Usage:  "Get an instance",
				Action: instanceGet,
			},
			{
				Name:    "list",
				Aliases: []string{"ls"},
				Usage:   "Query instances",
				Action:  instanceList,
			},
			{
				Name:    "delete",
				Aliases: []string{"rm"},
				Usage:   "Delete an instance",
				Action:  instanceDelete,
			},
			{
				Name:   "update",
				Usage:  "Update and existing instance",
				Flags:  instanceUpdateFlags,
				Action: instanceUpdate,
			},
			applicationCommand,
		},
	}
)

func instanceCreate(c *cli.Context) error {
	var err error
	var inst hiro.Instance

	conn, err := rpcClient(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	h := pb.NewHiroClient(conn)

	lifetime := time.Duration(c.Duration("token_lifetime"))
	if lifetime == 0 {
		lifetime = hiro.DefaultTokenLifetime
	}

	sessionLifetime := c.Duration("session-lifetime")
	if sessionLifetime == 0 {
		sessionLifetime = hiro.DefaultSessionLifetime
	}

	perms := c.StringSlice("permissions")
	if len(perms) == 0 {
		perms = hiro.Scopes
	}

	params := &pb.InstanceCreateRequest{
		Name:            c.String("name"),
		Description:     ptr.NilString(c.String("description")),
		TokenLifetime:   ptr.Uint64(uint64(lifetime.Seconds())),
		Permissions:     make([]*pb.Instance_Permission, 0),
		SessionLifetime: ptr.Uint64(uint64(sessionLifetime.Seconds())),
	}

	for _, p := range perms {
		params.Permissions = append(params.Permissions, &pb.Instance_Permission{
			Permission: p,
		})
	}

	a, err := h.InstanceCreate(context.Background(), params)
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

	inst.FromProto(a)

	fmt.Printf("Instance %s [%s] created.\n", inst.Name, inst.ID)

	dumpValue(inst)

	return err
}

func instanceGet(c *cli.Context) error {
	var inst hiro.Instance

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

	inst.FromProto(rval)

	dumpValue(inst)

	return nil
}

func instanceDelete(c *cli.Context) error {
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

		fmt.Println("instance deleted")
		fmt.Println()
	} else {
		fmt.Println("operation cancelled")
	}

	return nil
}

func instanceList(c *cli.Context) error {
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

	insts, err := h.InstanceList(context.Background(), &pb.InstanceListRequest{})
	if err != nil {
		return err
	}

	list := make([]entry, 0)

	for {
		a, err := insts.Recv()
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

func instanceUpdate(c *cli.Context) error {
	var err error

	conn, err := rpcClient(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	h := pb.NewHiroClient(conn)

	params := pb.InstanceUpdateRequest{
		Id: c.String("id"),
		Permissions: &pb.InstanceUpdateRequest_PermissionUpdate{
			Add:    make([]*pb.Instance_Permission, 0),
			Remove: make([]*pb.Instance_Permission, 0),
		},
	}

	lifetime := uint64(c.Duration("token_lifetime"))
	if lifetime > 0 {
		params.TokenLifetime = &lifetime
	}

	sessionLifetime := uint64(c.Duration("session_lifetime"))
	if sessionLifetime > 0 {
		params.SessionLifetime = &sessionLifetime
	}

	if name := c.String("name"); name != "" {
		params.Name = &name
	}

	if desc := c.String("description"); desc != "" {
		params.Description = &desc
	}

	if perms := c.StringSlice("add-permission"); len(perms) > 0 {
		for _, p := range perms {
			params.Permissions.Add = append(params.Permissions.Add, &pb.Instance_Permission{
				Permission: p,
			})
		}
	}

	if perms := c.StringSlice("rem-permission"); len(perms) > 0 {
		for _, p := range perms {
			params.Permissions.Remove = append(params.Permissions.Remove, &pb.Instance_Permission{
				Permission: p,
			})
		}
	}

	inst, err := h.InstanceUpdate(context.Background(), &params)
	if err != nil {
		return err
	}

	fmt.Printf("Instance %s [%s] updated.\n", inst.Name, inst.Id)

	dumpValue(inst)

	return err
}
