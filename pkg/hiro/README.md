# Hiro Application Platform

## Controller
The `hiro.Controller` interface is designed to built on-top of the `hiro.Backend` implementation, but it is abstracted into an interface to simplify testing and improve extensibility such that it could be provided over other interfaces easily like grpc.

The interface is responsbile for managing the CRUD operations and persistence of instances, applications, roles, users, and secrets.

### Instances

#### Secrets
### Applications

### Roles

### Users

## Daemon
The `hiro` service is the core platform component that provides all of the underlying services for higher level client implementations. The only dependencies are a `hiro.Controller`, an [`oauth.Controller`](../oauth/README.md) and a [`session.Controller`](../api/session/README.md). These three interfaces can be implemented by the same object.

### API Server
The service will ensure the core services are ready for platforms to utilize by creating both an [`api.Server`](../api/README.md#api-server) and a grpc.Server instance. The api server will always provide hiro services at the `/hiro/{version}` (i.e. `/hiro/1.0.0`) path.

This api is defined as an [Open API 2.0 (aka Swagger) spec](../../api/swagger/v1/hiro.swagger.yaml). And can be fetched from the service at `/hiro/{version}/swagger.{json|yaml}`.

#### Routes
The API routes are defined in the `route_*.go` modules. These are wrappers around the `hiro.Controller`, providing a REST/CRUD to the controller methods. Most of the routes are secured by the `oauth.Authorizer`.
### OAuth Controller
The `service` adds the [oauth controller](../oauth/README.md) to the path `/oauth`. This provides all of the neccessary authentication and authorization support for the api server. 

This api is defined as an [Open API 2.0 (aka Swagger) spec](../../api/swagger/v1/oauth.swagger.yaml). And can be fetched from the service at `/oauth/swagger.{json|yaml}`.

### RPC Server

### Scheduler
