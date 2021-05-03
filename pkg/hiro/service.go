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

package hiro

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/ModelRocket/hiro/pkg/api"
	"github.com/ModelRocket/hiro/pkg/api/session"
	"github.com/ModelRocket/hiro/pkg/env"
	"github.com/ModelRocket/hiro/pkg/hiro/pb"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/apex/log"
	"github.com/go-co-op/gocron"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/soheilhy/cmux"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type (
	// Service is the core hiro service object
	// Platoform projects use the hiro.Service to provide services
	Service struct {
		name        string
		apiServer   *api.Server
		apiOptions  []api.Option
		rpcServer   *grpc.Server
		webRPCPath  string
		backOptions []BackendOption
		ctrl        Controller
		oauthPath   string
		hiroPath    string
		oauthCtrl   oauth.Controller
		sessionCtrl session.Controller
		sessionMgr  *session.Manager
		serverAddr  string
		shutdown    chan int
		wg          sync.WaitGroup
		sched       *gocron.Scheduler
		log         log.Interface
	}

	// Job is a job handler that the service will schedule
	Job struct {
		Function interface{}
		Params   []interface{}
		Interval time.Duration
		At       *time.Time
	}

	// ServiceOption is a service option
	ServiceOption func(d *Service)
)

// NewService creates a new service object
func NewService(opts ...ServiceOption) (*Service, error) {
	const (
		localServerAddr   = "127.0.0.0:9000"
		defaultHiroPath   = "/hiro"
		defaultOAuthPath  = "/oauth"
		defaultWebRPCPath = "/rpc"
		defaultName       = "hiro"
	)

	var (
		defaultServerAddr = env.Get("HIRO_SERVER_ADDR", localServerAddr)
	)

	d := &Service{
		name:        defaultName,
		serverAddr:  defaultServerAddr,
		apiOptions:  []api.Option{api.WithLog(log.Log)},
		backOptions: []BackendOption{Automigrate(), Initialize()},
		hiroPath:    defaultHiroPath,
		oauthPath:   defaultOAuthPath,
		webRPCPath:  defaultWebRPCPath,
		shutdown:    make(chan int),
		sched:       gocron.NewScheduler(time.UTC),
		log:         log.Log,
	}

	for _, opt := range opts {
		opt(d)
	}

	d.log = log.WithField("service", d.name)

	if d.ctrl == nil {
		back, err := New(d.backOptions...)
		if err != nil {
			return nil, err
		}

		d.ctrl = back
	}

	if d.oauthCtrl == nil {
		d.oauthCtrl = OAuthController(d.ctrl)
	}

	// The oauth.Controller doesn't define how tokens are managed, hiro
	// starts a cron job to ensure expired and revoked tokens are periodically
	// removed from the database or are at least marked unusable.
	d.sched.Every(uint64(env.Duration("TOKEN_CLEANUP_INTERVAL", time.Minute*15).Minutes())).
		Minutes().
		StartImmediately().
		Do(d.oauthCtrl.TokenCleanup, context.Background())

	if d.sessionCtrl == nil {
		d.sessionCtrl = SessionController(d.ctrl)
	}

	// start the session cleanup job, same purpose as the token cleanup
	d.sched.Every(uint64(env.Duration("SESSION_CLEANUP_INTERVAL", time.Minute*15).Minutes())).
		Minutes().
		StartImmediately().
		Do(d.sessionCtrl.SessionCleanup, context.Background())

	if d.apiServer == nil {
		d.apiServer = api.NewServer(d.apiOptions...)
	}

	d.sessionMgr = session.NewManager(d.sessionCtrl)

	// setup the oauth router
	d.apiServer.Router(
		d.oauthPath,
		api.WithContext(d.oauthCtrl),
		api.WithSessionManager(d.sessionMgr),
		api.WithAuthorizers(oauth.Authorizer(oauth.WithPermitQueryToken(true)))).
		AddRoutes(oauth.Routes()...)

	// setup the hiro router
	d.apiServer.Router(
		d.hiroPath,
		api.WithVersioning("1.0.0"),
		api.WithContext(d.ctrl), api.WithAuthorizers(oauth.Authorizer())).
		AddRoutes(Routes()...)

	if d.rpcServer == nil {
		d.rpcServer = grpc.NewServer(
			// add handlers to ensure rpc calls are secured by oauth tokens
			grpc.UnaryInterceptor(d.validateTokenUnary),
			grpc.StreamInterceptor(d.validateTokenStream),
		)
	}

	// register the hiro rpc server
	pb.RegisterHiroServer(d.rpcServer, NewRPCServer(d.ctrl))

	// add grpc-web support
	ws := grpcweb.WrapServer(d.rpcServer)

	d.apiServer.Router(d.webRPCPath).Mux.
		Headers("Content-Type", "application/grpc-web").
		Handler(ws)

	d.sched.StartAsync()

	return d, nil
}

// WithName sets the service name
func WithName(name string) ServiceOption {
	return func(d *Service) {
		d.name = name
	}
}

// WithServerAddr sets the service listening address
func WithServerAddr(addr string) ServiceOption {
	return func(s *Service) {
		s.serverAddr = addr
	}
}

// WithBackendOptions sets backend options
func WithBackendOptions(o []BackendOption) ServiceOption {
	return func(s *Service) {
		s.backOptions = o
	}
}

// WithController sets the service controller
func WithController(c Controller) ServiceOption {
	return func(s *Service) {
		s.ctrl = c
	}
}

// WithOAuthController set the service oauth controller
func WithOAuthController(o oauth.Controller) ServiceOption {
	return func(s *Service) {
		s.oauthCtrl = o
	}
}

// WithSessionController set the service session controller
func WithSessionController(c session.Controller) ServiceOption {
	return func(s *Service) {
		s.sessionCtrl = c
	}
}

// WithAPIServer sets the service api server; mutally exclusive with WithAPIOptions
func WithAPIServer(srv *api.Server) ServiceOption {
	return func(s *Service) {
		s.apiServer = srv
	}
}

// WithAPIOptions sets api server options; mutally exclusive with WithAPIServer
func WithAPIOptions(o ...api.Option) ServiceOption {
	return func(s *Service) {
		s.apiOptions = append(s.apiOptions, o...)
	}
}

// WithRPCServer sets the service rpc server
func WithRPCServer(r *grpc.Server) ServiceOption {
	return func(s *Service) {
		s.rpcServer = r
	}
}

// Run starts the service, blocks and handle interrupts
func (d *Service) Run() error {
	done := make(chan os.Signal, 1)

	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := d.Serve(func() {
			d.log.Infof("service started %s", d.serverAddr)
		}); err != nil {
			d.log.Fatalf("failed to start the hiro service %+v", err)
		}
	}()

	<-done
	log.Info("dameon shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return d.Shutdown(ctx)
}

// Serve starts the dameon server
func (d *Service) Serve(ready func()) error {
	l, err := net.Listen("tcp", d.serverAddr)
	if err != nil {
		return err
	}

	// add a shutdown handler
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()

		for {
			select {
			case <-d.shutdown:
				l.Close()
				return
			}
		}
	}()

	// create the multiplexer
	m := cmux.New(l)
	grpcL := m.MatchWithWriters(cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"))
	httpL := m.Match(cmux.HTTP1Fast())

	// use an error group to collect errors
	errs := new(errgroup.Group)

	// start the http server
	errs.Go(func() error {
		s := &http.Server{Handler: d.apiServer}

		if err := s.Serve(httpL); err != nil && err != cmux.ErrListenerClosed {
			return err
		}

		return nil
	})

	// start the rpc server
	errs.Go(func() error {
		if err := d.rpcServer.Serve(grpcL); err != nil && err != cmux.ErrListenerClosed {
			return err
		}

		return nil
	})

	// start the mux
	errs.Go(m.Serve)

	ready()

	return errs.Wait()
}

// Shutdown terminates the service services
func (d *Service) Shutdown(ctx context.Context) error {
	done := make(chan bool)

	d.sched.Stop()

	go func() {
		close(d.shutdown)
		d.wg.Wait()
		done <- true
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-done:
			return nil
		}
	}
}

// AddJob adds a job to the service scheduler
func (d *Service) AddJob(job Job) error {
	j := d.sched.Every(uint64(job.Interval.Seconds())).Seconds()

	if job.At != nil {
		j = j.At(job.At.UTC().Format("15:04:05"))
	}

	j.Do(job.Function, job.Params...)

	return nil
}

// RPCServer returns the rpc server services can register with
func (d *Service) RPCServer() *grpc.Server {
	return d.rpcServer
}

// APIServer returns the api server that services can register with
func (d *Service) APIServer() *api.Server {
	return d.apiServer
}

func (d *Service) validateToken(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "missing metadata")
	}

	auth, ok := md["authorization"]
	if !ok || len(auth) == 0 {
		return status.Errorf(codes.Unauthenticated, "invalid token")
	}

	_, err := oauth.ParseBearer(auth[0], func(kid string, c oauth.Claims) (oauth.TokenSecret, error) {
		aud, err := d.oauthCtrl.AudienceGet(ctx, c.Audience())
		if err != nil {
			return nil, err
		}

		for _, s := range aud.Secrets() {
			if string(s.ID()) == kid {
				return s, nil
			}
		}

		return nil, oauth.ErrKeyNotFound
	})
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "invalid token")
	}

	return nil
}

func (d *Service) validateTokenUnary(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := d.validateToken(ctx); err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

func (d *Service) validateTokenStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := d.validateToken(ss.Context()); err != nil {
		return err
	}

	return handler(srv, ss)
}
