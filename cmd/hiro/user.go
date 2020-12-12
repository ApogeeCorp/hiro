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
	"os"

	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/types"
	"github.com/dustin/go-humanize"
	"github.com/lensesio/tableprinter"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v2"
)

var (
	userCreateFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "login",
			Usage: "The user login",
		},
		&cli.StringFlag{
			Name:  "password",
			Usage: "The user password",
		},
		&cli.GenericFlag{
			Name:    "permissions",
			Aliases: []string{"p"},
			Usage:   "User permissions, in the format audience=perm1,perm2,permn",
			Value:   permArg{},
		},
	}

	userCommand = &cli.Command{
		Name:  "users",
		Usage: "User management",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "id",
				Usage: "The user id for querying by id",
			},
			&cli.StringFlag{
				Name:  "login",
				Usage: "The user login for querying by",
			},
		},
		Subcommands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "Create a new user",
				Flags:  userCreateFlags,
				Action: userCreate,
			},
			{
				Name:   "get",
				Usage:  "Get an user by id",
				Action: userGet,
			},
			{
				Name:    "list",
				Aliases: []string{"ls"},
				Usage:   "List all users",
				Action:  userList,
			},
			{
				Name:    "delete",
				Aliases: []string{"rm"},
				Usage:   "Delete an user by id",
				Action:  userDelete,
			},
			{
				Name:   "update",
				Usage:  "Update and existing user",
				Flags:  userCreateFlags,
				Action: userUpdate,
			},
		},
	}
)

func userCreate(c *cli.Context) error {
	var err error

	perms := oauth.ScopeSet(c.Generic("permissions").(permArg))

	// default to hiro permissions
	if len(perms) == 0 {
		perms = oauth.ScopeSet{
			"hiro": append(oauth.Scopes, hiro.Scopes...),
		}
	}

	h.PasswordManager().EnforcePasswordPolicy(false)

	user, err := h.UserCreate(context.Background(), hiro.UserCreateInput{
		Login:       c.String("login"),
		Password:    ptr.NilString(c.String("password")),
		Permissions: perms,
	})
	if err != nil {
		if errors.Is(err, hiro.ErrDuplicateObject) {
			fmt.Printf("User with login %s already exists\n", c.String("login"))
			return nil
		}
		return err
	}

	fmt.Printf("User %s [%s] created.\n", user.Login, user.ID)

	dumpValue(user)

	return err
}

func userGet(c *cli.Context) error {
	var params hiro.UserGetInput

	if id := types.ID(c.String("id")); id.Valid() {
		params.UserID = &id
	} else if login := c.String("login"); login != "" {
		params.Login = &login
	}

	app, err := h.UserGet(context.Background(), params)
	if err != nil {
		return err
	}

	dumpValue(app)

	return nil
}

func userDelete(c *cli.Context) error {
	id := types.ID(c.String("id"))

	prompt := promptui.Prompt{
		Label:     fmt.Sprintf("Delete User %s", id.String()),
		IsConfirm: true,
	}

	result, err := prompt.Run()
	if err != nil && err != promptui.ErrAbort {
		return err
	}

	if result == "y" {
		if err := h.UserDelete(context.Background(), hiro.UserDeleteInput{
			UserID: id,
		}); err != nil {
			return err
		}

		fmt.Println("user deleted")
		fmt.Println()
	} else {
		fmt.Println("operation cancelled")
	}

	return nil
}

func userList(c *cli.Context) error {
	users, err := h.UserList(context.Background(), hiro.UserListInput{})
	if err != nil {
		return err
	}

	fmt.Printf("Found %d user(s)\n\n", len(users))

	type entry struct {
		ID        types.ID `header:"id"`
		Login     string   `header:"login"`
		CreatedAt string   `header:"created_at"`
	}

	list := make([]entry, 0)
	for _, u := range users {
		list = append(list, entry{
			ID:        u.ID,
			Login:     u.Login,
			CreatedAt: humanize.Time(u.CreatedAt),
		})
	}
	tableprinter.Print(os.Stdout, list)
	fmt.Println()

	return nil
}

func userUpdate(c *cli.Context) error {
	var err error

	params := hiro.UserUpdateInput{
		UserID:      types.ID(c.String("id")),
		Permissions: oauth.ScopeSet(c.Generic("permissions").(permArg)),
	}

	user, err := h.UserUpdate(context.Background(), params)
	if err != nil {
		return err
	}

	fmt.Printf("User %s [%s] updated.\n", user.Login, user.ID)

	dumpValue(user)

	return err
}
