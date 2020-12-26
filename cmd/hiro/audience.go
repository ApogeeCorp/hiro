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
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"time"

	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/ModelRocket/hiro/pkg/hiro/pb"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/dustin/go-humanize"
	"github.com/johnsiilver/getcert"
	"github.com/lensesio/tableprinter"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	var err error

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

	aud, err := h.AudienceCreate(context.Background(), hiro.AudienceCreateInput{
		Name:            c.String("name"),
		Description:     ptr.NilString(c.String("description")),
		TokenLifetime:   lifetime,
		TokenAlgorithm:  oauth.TokenAlgorithm(c.String("token_algorithm")),
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

	if m := c.String("token_hmac"); m != "" {
		_, err = h.SecretCreate(context.Background(), hiro.SecretCreateInput{
			AudienceID: aud.ID,
			Type:       hiro.SecretTypeToken,
			Algorithm:  oauth.TokenAlgorithmHS256.Ptr(),
			Key:        ptr.String(m),
		})
	} else if r := c.Path("token_rsa"); r != "" {
		data, err := ioutil.ReadFile(r)
		if err != nil {
			return err
		}

		_, err = h.SecretCreate(context.Background(), hiro.SecretCreateInput{
			AudienceID: aud.ID,
			Type:       hiro.SecretTypeToken,
			Algorithm:  oauth.TokenAlgorithmRS256.Ptr(),
			Key:        ptr.String(base64.RawURLEncoding.EncodeToString(data)),
		})
	} else {
		_, err = h.SecretCreate(context.Background(), hiro.SecretCreateInput{
			AudienceID: aud.ID,
			Type:       hiro.SecretTypeToken,
			Algorithm:  aud.TokenAlgorithm.Ptr(),
		})
	}

	// generate a new session secret
	_, err = h.SecretCreate(context.Background(), hiro.SecretCreateInput{
		AudienceID: aud.ID,
		Type:       hiro.SecretTypeSession,
		Algorithm:  oauth.TokenAlgorithmHS256.Ptr(),
	})
	if err != nil {
		return err
	}

	fmt.Printf("Audiece %s [%s] created.\n", aud.Name, aud.ID)

	dumpValue(aud)

	return err
}

func audienceGet(c *cli.Context) error {
	var params hiro.AudienceGetInput

	if id := hiro.ID(c.String("id")); id.Valid() {
		params.AudienceID = id
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
	id := hiro.ID(c.String("id"))

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
	type entry struct {
		ID          hiro.ID `header:"id"`
		Name        string  `header:"name"`
		Description string  `header:"description"`
		CreatedAt   string  `header:"created_at"`
	}

	u, err := url.Parse(c.String("api-host"))
	if err != nil {
		return err
	}

	creds, err := oauth.ClientCredentials(clientcredentials.Config{
		TokenURL:       fmt.Sprintf("%s/oauth/token", u.String()),
		EndpointParams: url.Values{"audience": []string{c.String("audience")}},
		ClientID:       c.String("client-id"),
		ClientSecret:   c.String("client-secret"),
		AuthStyle:      oauth2.AuthStyleInParams,
		Scopes:         []string{},
	}, !c.Bool("rpc-no-tls"))

	var conn *grpc.ClientConn

	if !c.Bool("rpc-no-tls") {
		tlsCert, _, err := getcert.FromTLSServer(u.String(), true)
		if err != nil {
			return err
		}

		conn, err = grpc.Dial(
			u.Host,
			grpc.WithTransportCredentials(
				credentials.NewTLS(
					&tls.Config{
						ServerName:         c.String("api-host"),
						Certificates:       []tls.Certificate{tlsCert},
						ClientAuth:         tls.NoClientCert,
						InsecureSkipVerify: true,
					})),
			grpc.WithPerRPCCredentials(creds))
	} else {
		conn, err = grpc.Dial(
			u.Host,
			grpc.WithInsecure(),
			grpc.WithPerRPCCredentials(creds),
		)
	}
	if err != nil {
		return err
	}

	defer conn.Close()

	h := pb.NewHiroClient(conn)

	auds, err := h.AudienceList(context.Background(), &pb.AudienceListRequest{})
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

	params := hiro.AudienceUpdateInput{
		AudienceID: hiro.ID(c.String("id")),
	}

	lifetime := c.Duration("token_lifetime")
	if lifetime > 0 {
		params.TokenLifetime = &lifetime
	}

	sessionLifetime := c.Duration("session_lifetime")
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
		params.Permissions = &hiro.AudiencePermissionsUpdate{Add: oauth.Scope(perms)}
	}

	aud, err := h.AudienceUpdate(context.Background(), params)
	if err != nil {
		return err
	}

	if m := c.String("token_hmac"); m != "" {
		_, err = h.SecretCreate(context.Background(), hiro.SecretCreateInput{
			AudienceID: aud.ID,
			Type:       hiro.SecretTypeToken,
			Algorithm:  oauth.TokenAlgorithmHS256.Ptr(),
			Key:        ptr.String(m),
		})
	} else if r := c.Path("token_rsa"); r != "" {
		data, err := ioutil.ReadFile(r)
		if err != nil {
			return err
		}
		_, err = h.SecretCreate(context.Background(), hiro.SecretCreateInput{
			AudienceID: aud.ID,
			Type:       hiro.SecretTypeToken,
			Algorithm:  oauth.TokenAlgorithmHS256.Ptr(),
			Key:        ptr.String(base64.RawURLEncoding.EncodeToString(data)),
		})
	}

	fmt.Printf("Audiece %s [%s] updated.\n", aud.Name, aud.ID)

	dumpValue(aud)

	return err
}
