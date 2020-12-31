# Hiro

Model Rocket Hiro Project

This project is used by Model Rocket client projects to provide a common foundation for custom platforms. 

`hiro` is not meant to be used as a standalone project.

Developing with the project requires `go 1.14` or greater.

## Project Layout
This project follows the [Standard go Project Layout](https://github.com/golang-standards/project-layout)

```
~~~
├── api/                        // API definitions
|   └── proto                   // gRPC protocol definitions
|   └── swagger                 // Swagger/OpenAPI 2.0 definitions
├── cmd/                        // Project executables
|   └── hiro/                   // The hiro tool
├── db/                         // The default database components
|   └── sql /                   // Postgres SQL scripts
├── pkg/                        // Library packages
|   └── hiro/                   // The hiro platform
|   └── pb/                     // The hiro protocol buffers platform
├── LICENSE                     // The project license
├── Makefile                    // The project Makefile

~~~
```

## Pre-requisites
All projects based on hiro require postgres12+.
## Core Components
The core `hiro` platform components are:

1. [`api`](./pkg/api/README.md) - API Services Library for simplifying REST APIs, authorizations, etc.
1. [`oauth`](./pkg/oauth/README.md) - OAuth 2.0 library for 
1. [`hiro`](./pkg/hiro/README.md) - The Hiro Platform for managing apis, applications, users, and more.

## Hiro Tool
The `hiro` tool provides command line support to running instances of hiro applications. More details are in its [README.md](./cmd/hiro/README.md).