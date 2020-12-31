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

	"github.com/ModelRocket/hiro/pkg/pb"
	"github.com/ModelRocket/sparks/pkg/oauth"
	"github.com/ModelRocket/reno/pkg/env"
	"github.com/ModelRocket/sparks/pkg/api"
	"github.com/ModelRocket/sparks/pkg/api/session"
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
	// Daemon is the core hiro service object
	// Platoform projects use the hiro.Daemon to provide services
	Daemon struct {
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

	// Job is a job handler that the daemon will schedule
	Job struct {
		Function interface{}
		Params   []interface{}
		Interval time.Duration
		At       *time.Time
	}

	// DaemonOption is a daemon option
	DaemonOption func(d *Daemon)
)

// NewDaemon creates a new daemon object
func NewDaemon(opts ...DaemonOption) (*Daemon, error) {
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

	d := &Daemon{
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

	d.log = log.WithField("daemon", d.name)

	if d.ctrl == nil {
		back, err := New(d.backOptions...)
		if err != nil {
			return nil, err
		}

		d.ctrl = back
	}

	if d.oauthCtrl == nil {
		d.oauthCtrl = d.ctrl.OAuthController()
	}

	// The oauth.Controller doesn't define how tokens are managed, hiro
	// starts a cron job to ensure expired and revoked tokens are periodically
	// removed from the database.
	d.sched.Every(uint64(env.Duration("TOKEN_CLEANUP_INTERVAL", time.Minute*15).Minutes())).
		Minutes().
		StartImmediately().
		Do(d.oauthCtrl.TokenCleanup, context.Background())

	if d.sessionCtrl == nil {
		d.sessionCtrl = d.ctrl.SessionController()
	}

	// start the session cleanup job, as purpose as the token cleanup
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
		api.WithContext(d.ctrl),		api.WithAuthorizers(oauth.Authorizer())).

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

// WithName sets the daemon name
func WithName(name string) DaemonOption {
	return func(d *Daemon) {
		d.name = name
	}
}

// WithServerAddr sets the daemon listening address
func WithServerAddr(addr string) DaemonOption {
	return func(d *Daemon) {
		d.serverAddr = addr
	}
}

// WithBackendOptions sets backend options
func WithBackendOptions(o []BackendOption) DaemonOption {
	return func(d *Daemon) {
		d.backOptions = o
	}
}

// WithController sets the daemon controller
func WithController(c Controller) DaemonOption {
	return func(d *Daemon) {
		d.ctrl = c
	}
}

// WithOAuthController set the daemon oauth controller
func WithOAuthController(o oauth.Controller) DaemonOption {
	return func(d *Daemon) {
		d.oauthCtrl = o
	}
}

// WithSessionController set the daemon session controller
func WithSessionController(s session.Controller) DaemonOption {
	return func(d *Daemon) {
		d.sessionCtrl = s
	}
}

// WithAPIServer sets the daemon api server; mutally exclusive with WithAPIOptions
func WithAPIServer(s *api.Server) DaemonOption {
	return func(d *Daemon) {
		d.apiServer = s
	}
}

// WithAPIOptions sets api server options; mutally exclusive with WithAPIServer
func WithAPIOptions(o ...api.Option) DaemonOption {
	return func(d *Daemon) {
		d.apiOptions = append(d.apiOptions, o...)
	}
}

// WithRPCServer sets the daemon rpc server
func WithRPCServer(s *grpc.Server) DaemonOption {
	return func(d *Daemon) {
		d.rpcServer = s
	}
}

// Run starts the service, blocks and handle interrupts
func (d *Daemon) Run() error {
	done := make(chan os.Signal, 1)

	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := d.Serve(func() {
			d.log.Infof("daemon started %s", d.serverAddr)
		}); err != nil {
			d.log.Fatalf("failed to start the hiro daemon %+v", err)
		}
	}()

	<-done
	log.Info("dameon shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return d.Shutdown(ctx)
}

// Serve starts the dameon server
func (d *Daemon) Serve(ready func()) error {
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

// Shutdown terminates the daemon services
func (d *Daemon) Shutdown(ctx context.Context) error {
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

// AddJob adds a job to the daemon scheduler
func (d *Daemon) AddJob(job Job) error {
	j := d.sched.Every(uint64(job.Interval.Seconds())).Seconds()

	if job.At != nil {
		j = j.At(job.At.UTC().Format("15:04:05"))
	}

	j.Do(job.Function, job.Params...)

	return nil
}

// RPCServer returns the rpc server services can register with
func (d *Daemon) RPCServer() *grpc.Server {
	return d.rpcServer
}

// APIServer returns the api server that services can register with
func (d *Daemon) APIServer() *api.Server {
	return d.apiServer
}

func (d *Daemon) validateToken(ctx context.Context) error {
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

func (d *Daemon) validateTokenUnary(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := d.validateToken(ctx); err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

func (d *Daemon) validateTokenStream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := d.validateToken(ss.Context()); err != nil {
		return err
	}

	return handler(srv, ss)
}
