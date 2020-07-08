# Hiro

Hiro provides a common architecture for API services with an extensible backed interface.

Developing with the project requires `go 1.14` or greater.

## Default Backend Sevices

The default backend is Postgres. To start this backend you need the latest Docker installed.

```bash
$ docker-compose -f ./deployments/hiro/docker-compose.yml up
```

This will instantiate a local Postgres intance and prepare it for the api service.

## Running the service

There a few environment variables this service relies on. The following will connect to the
local Postgres and start the service on port 9000, with debug logging enabled.

```bash
$ export SERVER_ADDR="0.0.0.0:9000"
$ export LOG_LEVEL="debug"
$ export DB_SOURCE="postgres://postgres:password@localhost:5432/hiro?sslmode=disable"
$ go run ./cmd/hiro
```
