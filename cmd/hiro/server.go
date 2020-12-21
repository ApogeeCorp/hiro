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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apex/log"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/urfave/cli/v2"
)

func serverMain(c *cli.Context) error {
	d, err := hiro.NewDaemon(
		hiro.WithServerAddr(c.String("server-addr")),
		hiro.WithController(h),
		hiro.WithAPIOptions(
			api.WithTracing(c.Bool("http-tracing")),
			api.WithCORS(c.StringSlice("cors-allowed-origin")...)),
	)
	if err != nil {
		return err
	}

	done := make(chan os.Signal, 1)

	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := d.Serve(func() {
			log.Infof("hiro daemon started %s", c.String("server-addr"))
		}); err != nil {
			log.Fatalf("failed to start the hiro daemon %+v", err)
		}
	}()

	<-done
	log.Info("hiro dameon shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown:%+v", err)
	}
	log.Info("hiro shutdown")

	return nil
}
