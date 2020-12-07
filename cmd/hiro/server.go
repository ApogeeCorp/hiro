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
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/ModelRocket/hiro/pkg/hiro"
	"github.com/ModelRocket/hiro/pkg/hiro/pb"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
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

	ws := grpcweb.WrapServer(s)

	router := mux.NewRouter()

	router.PathPrefix("/").HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc-web") {
				ws.ServeHTTP(w, r)
			} else {
				http.DefaultServeMux.ServeHTTP(w, r)
			}
		})

	handler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"OPTIONS", "HEAD", "GET", "POST", "PUT", "DELETE"}),
		handlers.AllowedHeaders([]string{
			"Access-Control-Allow-Origin",
			"Accept",
			"Accept-Encoding",
			"Connection",
			"Origin",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Dest",
			"Referer",
			"Accept-Language",
			"Access-Control-Request-Method",
			"Access-Control-Request-Headers",
			"Cache-Control",
			"User-Agent",
			"Pragma",
			"X-Grpc-Web",
			"X-User-Agent",
			"Sec-Fetch-Site",
			"Accept-Encoding",
			"Content-Type",
			"Authorization",
		}),
		handlers.ExposedHeaders([]string{
			"Access-Control-Allow-Origin",
		}),
		handlers.AllowCredentials(),
	)

	http.ListenAndServe(c.String("http-addr"), handler(router))

	return nil
}
