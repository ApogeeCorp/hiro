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

package main

import (
	"context"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Teralytic/teralytic/api/server"
	"github.com/Teralytic/teralytic/pkg/daemon"
	"github.com/caarlos0/env/v6"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"

	// Register the timescaledb backend
	_ "github.com/Teralytic/teralytic/pkg/backend/timescale"
)

var (
	app = cli.NewApp()

	log = logrus.StandardLogger()

	config daemon.Config
)

func main() {
	app.Name = "teralytic"
	app.Usage = "Teralytic Service"
	app.Action = daemonMain
	app.Version = server.Version

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Usage:   "the configuration file",
			Aliases: []string{"f"},
			Value:   "/etc/teralytic/config.yaml",
			EnvVars: []string{"CONFIG_FILE"},
		},
		&cli.StringFlag{
			Name:    "log-level",
			Usage:   "set the logging level",
			Value:   "info",
			EnvVars: []string{"LOG_LEVEL"},
		},
	}

	app.Before = func(c *cli.Context) error {
		data, err := ioutil.ReadFile(c.String("config"))
		if err != nil && !os.IsNotExist(err) {
			return err
		}

		// load config from the file
		if data != nil {
			if err := yaml.Unmarshal(data, &config); err != nil {
				return err
			}
		}

		// bring in the env overrides
		if err := env.Parse(&config); err != nil {
			return err
		}

		if config.LogLevel != "" {
			if level, err := logrus.ParseLevel(config.LogLevel); err == nil {
				log.SetLevel(level)
			}
		}

		config.Logger = log

		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err)
	}
}

func daemonMain(c *cli.Context) error {
	d, err := daemon.New(config)
	if err != nil {
		return err
	}

	done := make(chan os.Signal, 1)

	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := d.Run(); err != nil {
			log.Fatalf("failed to start the teralytic daemon %+v", err)
		}
	}()
	log.Infof("teralytic daemon started")

	<-done
	log.Info("teralytic dameon shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown:%+v", err)
	}
	log.Infof("teralytic shutdown")

	return nil
}
