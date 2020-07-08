# The API

The API is comprised of these components

- `api/swagger.yaml` The OpenAPI 2.0 API definition document.
- `api/types` The generated API models shared by all components.
- `api/server` The REST API server that implements the spec operations.
- `pkg/client` The REST API client that implements a go library for accessing the API from other projects.

## API Generation

Generating the API types is handled by the `Makefile` which executes `hack/generate-swagger-api.sh` via
the `quay.io/goswagger/swagger:latest` Docker container for [goswagger](https://goswagger.io/). The
generation script relies on `api/swagger-gen.yaml` to handle some minor customizationa of the code
building.

After making changes to `api/swagger.yaml` you need to run the following in the workspace root:

```bash
> make api-gen
```

## API Documenation

To view API docs you run `make api-docs`. This will start a service on [localhost](http://localhost:8002).

## Consumable API

The spec at `api/swagger.yaml` include remote specs from other components. The generation script will
produce `api/swagger-flat.yaml` that can be used by external resources and is exposed at the `api/<version>/swagger.json`
endpoint.
