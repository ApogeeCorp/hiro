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
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/dustin/go-humanize"
	"github.com/lensesio/tableprinter"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v2"
)

var (
	applicationCreateFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Usage: "The application name",
		},
		&cli.StringFlag{
			Name:  "description",
			Usage: "The application description",
		},
		&cli.StringFlag{
			Name:  "type",
			Usage: "The application type",
			Value: "web",
		},
		&cli.StringSliceFlag{
			Name:    "permissions",
			Aliases: []string{"p"},
			Usage:   "Application permissions",
		},
		&cli.StringSliceFlag{
			Name:    "grants",
			Aliases: []string{"g"},
			Usage:   "Application grants",
		},
		&cli.StringSliceFlag{
			Name:    "application-endpoint",
			Aliases: []string{"aep"},
			Usage:   "Specify the authorized application endpoints for this application",
		},
		&cli.StringSliceFlag{
			Name:    "redirect-endpoint",
			Aliases: []string{"rep"},
			Usage:   "Specify the authorized redirect endpoints for this application",
		},
	}

	applicationCommand = &cli.Command{
		Name:    "application",
		Aliases: []string{"app", "apps"},
		Usage:   "Application management",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "id",
				Usage: "The application id for querying by id",
			},
			&cli.StringFlag{
				Name:  "name",
				Usage: "The application name for querying by",
			},
		},
		Subcommands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create a new application",
				Flags:  applicationCreateFlags,
				Action: applicationCreate,
			},
			{
				Name:   "get",
				Usage:  "Get an application by id",
				Action: applicationGet,
			},
			{
				Name:    "list",
				Aliases: []string{"ls"},
				Usage:   "List all applications",
				Action:  applicationList,
			},
			{
				Name:    "delete",
				Aliases: []string{"rm"},
				Usage:   "Delete an application by id",
				Action:  applicationDelete,
			},
			{
				Name:   "update",
				Usage:  "Update and existing application",
				Flags:  applicationCreateFlags,
				Action: applicationUpdate,
			},
		},
	}
)

func applicationCreate(c *cli.Context) error {

	return nil
}

func applicationGet(c *cli.Context) error {

	return nil
}

func applicationDelete(c *cli.Context) error {
	id := hiro.ID(c.String("id"))

	prompt := promptui.Prompt{
		Label:     fmt.Sprintf("Delete Application %s", id.String()),
		IsConfirm: true,
	}

	result, err := prompt.Run()
	if err != nil && err != promptui.ErrAbort {
		return err
	}

	if result == "y" {
		if err := h.ApplicationDelete(context.Background(), hiro.ApplicationDeleteInput{
			ApplicationID: id,
		}); err != nil {
			return err
		}

		fmt.Println("application deleted")
		fmt.Println()
	} else {
		fmt.Println("operation cancelled")
	}

	return nil
}

func applicationList(c *cli.Context) error {
	apps, err := h.ApplicationList(context.Background(), hiro.ApplicationListInput{})
	if err != nil {
		return err
	}

	fmt.Printf("Found %d application(s)\n\n", len(apps))

	type entry struct {
		ID          hiro.ID `header:"id"`
		Name        string  `header:"name"`
		Description string  `header:"description"`
		CreatedAt   string  `header:"created_at"`
	}

	list := make([]entry, 0)
	for _, a := range apps {
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

func applicationUpdate(c *cli.Context) error {
	return nil
}
