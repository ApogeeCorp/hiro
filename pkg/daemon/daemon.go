//
//  TERALYTIC CONFIDENTIAL
//  _________________
//   2020 TERALYTIC
//   All Rights Reserved.
//
//   NOTICE:  All information contained herein is, and remains
//   the property of TERALYTIC and its suppliers,
//   if any.  The intellectual and technical concepts contained
//   herein are proprietary to TERALYTIC
//   and its suppliers and may be covered by U.S. and Foreign Patents,
//   patents in process, and are protected by trade secret or copyright law.
//   Dissemination of this information or reproduction of this material
//   is strictly forbidden unless prior written permission is obtained
//   from TERALYTIC.
//

// Package daemon is the teralytic service manager
package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"sync"

	"github.com/Teralytic/oauth/pkg/oauth"
	"github.com/Teralytic/teralytic/api/server"
	"github.com/Teralytic/teralytic/pkg/teralytic"
	"github.com/a8m/rql"
	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"

	oauthsrv "github.com/Teralytic/oauth/api/server"
	"github.com/Teralytic/teralytic/api/types"
)

type (
	// Daemon is the daemon service object that hosts the api and the primary application
	// The daemon is responsible for connecting the API and initializing the backend interfaces.
	Daemon struct {
		server     *server.Server
		authServer *oauthsrv.Server
		backend    teralytic.Backend
		config     Config
		shutdown   chan int
		wg         sync.WaitGroup
	}
)

const (
	// AdminPrefix is the server admin static assets prefix
	AdminPrefix = "/"

	// AppPrefix is the server app prefix
	AppPrefix = "/app"
)

// New retuns a new daemon
func New(c Config) (*Daemon, error) {
	d := &Daemon{
		shutdown: make(chan int),
		config:   c,
	}

	backend, err := teralytic.Initialize(c.Backend, d)
	if err != nil {
		return nil, err
	}
	d.backend = backend
	c.Logger.Debug("backend providers initialized")

	// initialize the server api application
	if err := d.createServerApp(); err != nil {
		return nil, err
	}

	if err := d.createRootUser(); err != nil {
		return nil, err
	}

	// initialize the api server
	server := server.New(
		backend,
		d,
		server.WithLogger(c.Logger),
		server.WithAddr(c.ServerAddr),
	)
	d.server = server

	// generate the rsa private key the auth server will use to sign tokens
	key, err := d.generateServerKey()
	if err != nil {
		return nil, err
	}

	authServer := oauthsrv.New(
		d,
		key,
		oauthsrv.WithRouter(server.Router()),
		oauthsrv.WithLogger(c.Logger),
	)
	d.authServer = authServer

	c.Logger.Debug("api server initialized")

	server.Router().PathPrefix(AppPrefix).
		Handler(http.StripPrefix(AppPrefix, http.FileServer(http.Dir("./web/build"))))

	server.Router().PathPrefix(AdminPrefix).
		HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "./web/static/index.html")
		})

	c.Logger.Debug("server app initialized")

	return d, nil
}

// Run starts the daemon services
func (d *Daemon) Run() error {
	if err := d.server.Serve(); err != nil {
		return err
	}

	d.wg.Add(1)
	defer d.wg.Done()

	for {
		select {
		case <-d.shutdown:
			return nil
		}
	}
}

// Shutdown terminates the daemon services
func (d *Daemon) Shutdown(ctx context.Context) error {
	if err := d.server.Shutdown(ctx); err != nil {
		return err
	}

	d.shutdown <- 1

	d.wg.Wait()

	return nil
}

// Log implements the teralytic.BackendController interface
func (d *Daemon) Log() *logrus.Logger {
	return d.config.Logger
}

func (d *Daemon) generateServerKey() (*rsa.PrivateKey, error) {
	var priv string

	if err := d.backend.OptionGet("server:private_key", &priv); err != nil {
		if err != teralytic.ErrOptionNotFound {
			return nil, err
		}

		// generate a key
		reader := rand.Reader
		key, err := rsa.GenerateKey(reader, 2048)
		if err != nil {
			return nil, err
		}

		// output the private key
		privOut := new(bytes.Buffer)
		privKey := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}

		if err := pem.Encode(privOut, privKey); err != nil {
			return nil, err
		}

		if err := d.backend.OptionUpdate("server:private_key", base64.StdEncoding.EncodeToString(privOut.Bytes())); err != nil {
			return nil, err
		}

		return key, nil
	}

	privKey, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		return nil, err
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(privKey)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (d *Daemon) createServerApp() error {
	app := &types.Application{
		Name:          "Teralytic",
		Description:   "Teralytic Soil Management and Research Tool",
		Type:          "web",
		LoginUris:     []string{"/login"},
		RedirectUris:  []string{"/", "/dashboard"},
		LogoutUris:    []string{"/login"},
		AllowedGrants: []string{oauth.GrantTypeAuthCode, oauth.GrantTypeRefreshToken, oauth.GrantTypeClientCredentials},
		Permissions:   append(server.Permissions, "openid", "profile", "offline_access"),
		TokenLifetime: 3600,
	}

	if err := d.backend.ApplicationCreate(app); err != nil {
		if err != teralytic.ErrObjectExists {
			return err
		}
		if err := d.backend.ApplicationUpdate(&rql.Query{
			Filter: map[string]interface{}{
				"name": "Teralytic",
			},
		}, app); err != nil {
			return err
		}
	}

	d.Log().Debugf("Application [%s] initialized client id [%s] client secret [%s]", app.Name, app.ClientID, app.ClientSecret)

	return nil
}

func (d *Daemon) createRootUser() error {
	user := &types.User{
		Login:       "admin",
		Permissions: server.Permissions,
		Profile: &types.Profile{
			Name: "Admin User",
		},
	}

	if err := d.backend.UserCreate(user, "password"); err != nil {
		if err != teralytic.ErrObjectExists {
			return err
		}
		if err := d.backend.UserUpdate(&rql.Query{
			Filter: map[string]interface{}{
				"login": "admin",
			},
		}, user); err != nil {
			return err
		}
	}

	return nil
}
