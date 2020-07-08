/*
 * Copyright (C) 2020 Model Rocket
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package daemon

import (
	"errors"
	"net/http"

	"github.com/ModelRocket/hiro/api/server"
	"github.com/ModelRocket/hiro/api/types"
	oauth "github.com/ModelRocket/oauth/api/types"
	"github.com/a8m/rql"
	"github.com/dgrijalva/jwt-go"
	"github.com/ulule/deepcopier"
)

// ApplicationGet should return an application for the specified client id
func (d *Daemon) ApplicationGet(client string) (*oauth.Application, error) {
	app := types.Application{}

	if err := d.backend.ApplicationGet(&rql.Query{
		Filter: map[string]interface{}{
			"client_id": client,
		},
	}, &app); err != nil {
		return nil, err
	}

	return &oauth.Application{
		Name:          app.Name,
		Description:   app.Description,
		Type:          app.Type,
		ClientID:      app.ClientID,
		ClientSecret:  app.ClientSecret,
		LoginUris:     app.LoginUris,
		RedirectUris:  app.RedirectUris,
		LogoutUris:    app.LogoutUris,
		AllowedGrants: app.AllowedGrants,
		Permissions:   app.Permissions,
	}, nil
}

// AudienceGet should return an audience for the specified name
func (d *Daemon) AudienceGet(name string) (*oauth.Audience, error) {
	if name != "hiro:api" {
		return nil, errors.New("audience not found")
	}

	return &oauth.Audience{
		Name:           "hiro:api",
		Description:    "Hiro API",
		Permissions:    append(server.Permissions, "openid", "profile", "offline_access"),
		TokenAlgorithm: "RS256",
		TokenLifetime:  3600,
	}, nil
}

// UserAuthenticate authenticates a user using the login and password
func (d *Daemon) UserAuthenticate(login string, password string) (*oauth.User, error) {
	user := types.User{}
	if err := d.backend.UserAuthenticate(login, password, &user); err != nil {
		return nil, err
	}

	profile := &oauth.Profile{}

	deepcopier.Copy(user.Profile).To(profile)

	return &oauth.User{
		Login:       user.Login,
		Permissions: user.Permissions,
		Profile:     profile,
	}, nil
}

// UserGet returns a user by subject
func (d *Daemon) UserGet(sub string) (*oauth.User, error) {
	user := types.User{}
	if err := d.backend.UserGet(&rql.Query{
		Filter: map[string]interface{}{
			"id": sub,
		},
	}, &user); err != nil {
		return nil, err
	}

	profile := &oauth.Profile{}

	deepcopier.Copy(user.Profile).To(profile)

	return &oauth.User{
		Login:       user.Login,
		Permissions: append(user.Permissions, "openid", "profile", "offline_access"),
		Profile:     profile,
	}, nil
}

// AuthorizeRequest handles the authorizer request
func (d *Daemon) AuthorizeRequest(r *http.Request, scope ...[]string) (*jwt.Token, error) {
	return d.authServer.AuthorizeRequest(r, scope...)
}
