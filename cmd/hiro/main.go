/*
 * Copyright (C) 2020 Model Rocket
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file in the root of this
 * workspace for details.
 */

package main

import (
	"context"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ModelRocket/hiro/api/server"
	"github.com/ModelRocket/hiro/pkg/daemon"
	"github.com/caarlos0/env/v6"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"

	// Register the timescaledb backend
	_ "github.com/ModelRocket/hiro/pkg/backend/postgres"
)

var (
	app = cli.NewApp()

	log = logrus.StandardLogger()

	config daemon.Config
)

func main() {
	app.Name = "hiro"
	app.Usage = "Hiro API Service"
	app.Action = daemonMain
	app.Version = server.Version

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Usage:   "the configuration file",
			Aliases: []string{"f"},
			Value:   "/etc/hiro/config.yaml",
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
			log.Fatalf("failed to start the daemon %+v", err)
		}
	}()
	log.Infof("daemon started")

	<-done
	log.Info("dameon shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown:%+v", err)
	}
	log.Infof("shutdown complete")

	return nil
}
