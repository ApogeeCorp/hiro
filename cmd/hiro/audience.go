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
	"github.com/dustin/go-humanize"
	"github.com/lensesio/tableprinter"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v2"
)

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
			Description: ptr.SafeString(a.Description),
			CreatedAt:   humanize.Time(a.CreatedAt),
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
