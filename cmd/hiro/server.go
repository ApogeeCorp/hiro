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
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/apex/log"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/ModelRocket/hiro/pkg/hiro/pb"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
)

func serverMain(c *cli.Context) error {
	lis, err := net.Listen("tcp", c.String("rpc-addr"))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()

	pb.RegisterHiroServer(s, hiro.NewServer(h))

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %s", err)
		}
	}()

	server := api.NewServer()

	server.Router("/oauth").AddRoutes(oauth.Routes(h)...)

	ws := grpcweb.WrapServer(s)

	server.Router("/").AddRoutes(api.NewRoute("", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc-web") {
			ws.ServeHTTP(w, r)
		}
	}))

	done := make(chan os.Signal, 1)

	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.Serve(); err != nil {
			log.Fatalf("failed to start the atomic daemon %+v", err)
		}

	}()
	log.Info("atomic daemon started")

	<-done
	log.Info("atomic dameon shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown:%+v", err)
	}
	log.Info("atomic shutdown")

	return nil
}
