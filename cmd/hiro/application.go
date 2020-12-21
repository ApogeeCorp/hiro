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
	"errors"
	"fmt"
	"os"
	"strings"

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
		&cli.GenericFlag{
			Name:    "permissions",
			Aliases: []string{"p"},
			Usage:   "Application permissions, in the format audience=perm1,perm2,permn",
			Value:   permArg{},
		},
		&cli.GenericFlag{
			Name:    "grants",
			Aliases: []string{"g"},
			Usage:   "Application grants, in the format audience=client_credentials,refresh_token",
			Value:   grantArg{},
		},
		&cli.StringSliceFlag{
			Name:  "uri",
			Usage: "Specify the authorized redirect uris for this application",
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

type (
	permArg  oauth.ScopeSet
	grantArg oauth.Grants
)

func applicationCreate(c *cli.Context) error {
	var err error

	perms := oauth.ScopeSet(c.Generic("permissions").(permArg))
	grants := oauth.Grants(c.Generic("grants").(grantArg))

	// default to hiro permissions
	if len(perms) == 0 {
		perms = oauth.ScopeSet{
			"hiro": append(oauth.Scopes, hiro.Scopes...),
		}
	}

	// default to safe grants
	if len(grants) == 0 {
		grants = oauth.Grants{
			"hiro": oauth.GrantList{
				oauth.GrantTypeAuthCode,
				oauth.GrantTypeClientCredentials,
				oauth.GrantTypeRefreshToken,
			},
		}
	}

	app, err := h.ApplicationCreate(context.Background(), hiro.ApplicationCreateInput{
		Name:        c.String("name"),
		Description: ptr.NilString(c.String("description")),
		Type:        oauth.ClientType(c.String("type")),
		Permissions: perms,
		Grants:      grants,
		URIs:        oauth.MakeURIList(c.StringSlice("uri")...),
	})
	if err != nil {
		if errors.Is(err, hiro.ErrDuplicateObject) {
			fmt.Printf("Application with name %s already exists\n", c.String("name"))
			return nil
		}
		return err
	}

	fmt.Printf("Application %s [%s] created.\n", app.Name, app.ID)

	dumpValue(app)

	return err
}

func applicationGet(c *cli.Context) error {
	var params hiro.ApplicationGetInput

	if id := types.ID(c.String("id")); id.Valid() {
		params.ApplicationID = &id
	} else if name := c.String("name"); name != "" {
		params.Name = &name
	}

	app, err := h.ApplicationGet(context.Background(), params)
	if err != nil {
		return err
	}

	dumpValue(app)

	return nil
}

func applicationDelete(c *cli.Context) error {
	id := types.ID(c.String("id"))

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
		ID          types.ID `header:"id"`
		Name        string   `header:"name"`
		Description string   `header:"description"`
		CreatedAt   string   `header:"created_at"`
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
	var err error

	params := hiro.ApplicationUpdateInput{
		ApplicationID: types.ID(c.String("id")),
		Permissions: &hiro.PermissionUpdate{
			Add:       oauth.ScopeSet(c.Generic("permissions").(permArg)),
			Overwrite: true,
		},
		Grants: oauth.Grants(c.Generic("grants").(grantArg)),
	}

	if name := c.String("name"); name != "" {
		params.Name = &name
	}

	if desc := c.String("description"); desc != "" {
		params.Description = &desc
	}

	if uris := c.StringSlice("uri"); len(uris) > 0 {
		params.URIs = oauth.MakeURIList(c.StringSlice("uri")...)
	}

	app, err := h.ApplicationUpdate(context.Background(), params)
	if err != nil {
		return err
	}

	fmt.Printf("Application %s [%s] updated.\n", app.Name, app.ID)

	dumpValue(app)

	return err
}

func (m permArg) Set(value string) error {
	parts := strings.Split(value, "=")
	if len(parts) == 0 {
		return nil
	}

	if len(parts) != 2 {
		return errors.New("argument requires two parts")
	}

	if m[parts[0]] == nil {
		m[parts[0]] = make([]string, 0)
	}

	m[parts[0]] = append(m[parts[0]], strings.Split(parts[1], ",")...)

	return nil
}

func (m permArg) String() string {
	return ""
}

func (m grantArg) Set(value string) error {
	parts := strings.Split(value, "=")
	if len(parts) == 0 {
		return nil
	}

	if len(parts) != 2 {
		return errors.New("argument requires two parts")
	}

	if m[parts[0]] == nil {
		m[parts[0]] = make([]oauth.GrantType, 0)
	}

	for _, s := range strings.Split(parts[1], ",") {
		m[parts[0]] = append(m[parts[0]], oauth.GrantType(s))
	}

	return nil
}

func (m grantArg) String() string {
	return ""
}
