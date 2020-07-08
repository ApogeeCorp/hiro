# Teralytic

The Teralytic client service provides the API and interfaces for managing an organization's properties, probes, and data.

Developing with the project requires `go 1.14` or greater.

## Backend Sevices

The default backend is TimescaleDB. To start this backend you need the latest Docker installed.

```bash
$ docker-compose -f ./deployments/teralytic/docker-compose.yml up
```

This will instantiate a local TimescaleDB intance and prepare it for the teralytic service.

## Running Teralytic

There a few environment variables this service relies on. The following will connect to the local TimescaleDB and
start the service on port 9000, with debug logging enabled.

```bash
$ export SERVER_ADDR="0.0.0.0:9000"
$ export LOG_LEVEL="debug"
$ export DB_SOURCE="postgres://postgres:password@localhost:5432/teralytic?sslmode=disable"
$ go run ./cmd/teralytic
```
