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
	"fmt"
	"os"

	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/dustin/go-humanize"
	"github.com/lensesio/tableprinter"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v2"
)

var (
	roleCreateFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Usage: "The role name",
		},
		&cli.StringFlag{
			Name:    "permissions",
			Aliases: []string{"p"},
			Usage:   "Role permissions",
		},
	}

	roleCommand = &cli.Command{
		Name:    "roles",
		Aliases: []string{"role"},
		Usage:   "Role management",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "id",
				Usage: "The role id for querying by id",
			},
			&cli.StringFlag{
				Name:  "name",
				Usage: "The role name for querying by",
			},
		},
		Subcommands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create a new role",
				Flags:  roleCreateFlags,
				Action: roleCreate,
			},
			{
				Name:   "get",
				Usage:  "Get an role by id",
				Action: roleGet,
			},
			{
				Name:    "list",
				Aliases: []string{"ls"},
				Usage:   "List all roles",
				Action:  roleList,
			},
			{
				Name:    "delete",
				Aliases: []string{"rm"},
				Usage:   "Delete an role by id",
				Action:  roleDelete,
			},
			{
				Name:   "update",
				Usage:  "Update and existing role",
				Flags:  roleCreateFlags,
				Action: roleUpdate,
			},
		},
	}
)

func roleCreate(c *cli.Context) error {
	return nil
}

func roleGet(c *cli.Context) error {
	var params hiro.RoleGetInput

	if id := hiro.ID(c.String("id")); id.Valid() {
		params.RoleID = &id
	} else if name := c.String("name"); name != "" {
		params.Name = &name
	}

	app, err := h.RoleGet(context.Background(), params)
	if err != nil {
		return err
	}

	dumpValue(app)

	return nil
}

func roleDelete(c *cli.Context) error {
	id := hiro.ID(c.String("id"))

	prompt := promptui.Prompt{
		Label:     fmt.Sprintf("Delete Role %s", id.String()),
		IsConfirm: true,
	}

	result, err := prompt.Run()
	if err != nil && err != promptui.ErrAbort {
		return err
	}

	if result == "y" {
		if err := h.RoleDelete(context.Background(), hiro.RoleDeleteInput{
			RoleID: id,
		}); err != nil {
			return err
		}

		fmt.Println("role deleted")
		fmt.Println()
	} else {
		fmt.Println("operation cancelled")
	}

	return nil
}

func roleList(c *cli.Context) error {
	roles, err := h.RoleList(context.Background(), hiro.RoleListInput{})
	if err != nil {
		return err
	}

	fmt.Printf("Found %d role(s)\n\n", len(roles))

	type entry struct {
		ID        hiro.ID `header:"id"`
		Name      string  `header:"name"`
		CreatedAt string  `header:"created_at"`
	}

	list := make([]entry, 0)
	for _, u := range roles {
		list = append(list, entry{
			ID:        u.ID,
			Name:      u.Name,
			CreatedAt: humanize.Time(u.CreatedAt),
		})
	}
	tableprinter.Print(os.Stdout, list)
	fmt.Println()

	return nil
}

func roleUpdate(c *cli.Context) error {
	return nil
}
