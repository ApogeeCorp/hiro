# Hiro

Model Rocket Hiro Project

This project is used by Model Rocket client projects to provide a common foundation for custom platforms. 

`hiro` is not meant to be used as a standalone project.

Developing with the project requires `go 1.14` or greater.

## Project Layout

This project follows the [Standard go Project Layout](https://github.com/golang-standards/project-layout)

```
~~~
├── api/                        // API definitions and services
│   └── server/                 // The hiro server implementation
|   └── swagger.yaml            // The api definition source
|   └── swagger-gen.yaml        // goswagger configuration
├── cmd/                        // Project executables
|   └── hiro/                   // The hiro tool
├── db/                         // The default database components
|   └── sql /                   // Postgres SQL scripts
├── deployments/                // Container and orchestration
|   └── hiro/                   // Atomic backend deployments
|       └── docker-compose.yml  // Docker compose script for backend services
├── pkg/                        // Library packages
|   └── hiro/                   // The hiro backend implementation
|   └── oauth/                  // The base oauth implementation
|   └── null/                   // SQL null helpers
|   └── ptr/                    // Pointer helpers
├── LICENSE                     // The project license
├── Makefile                    // The project Makefile

~~~
```