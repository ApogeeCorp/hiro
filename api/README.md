# The Hiro API

The Hiro API is comprised of these components

- `api/swagger.yaml` The OpenAPI 2.0 API definition document.
- `api/swagger-gen.yaml` Swagger generation configuration.
- `api/spec` The embedded api spec generated using the Makefile: `make api-gen`

## API Generation

The Atomic Open API 2.0 Spec is embedded into the server for simpler integration. The models and associated structs managed manually
due to the generated types being too complex. If new types or adjustments are necessary, both the `swagger.yaml` and appropriate
models in `pkg/hiro` must be updated.

After making changes to `api/swagger.yaml` you need to run the following in the workspace root:

```bash
> make api-gen
```

## API Documenation

To view API docs you run `make api-docs`. This will start a service on [localhost](http://localhost:8002).

# API Server

The primary purpose of the API Server is to parse, validate, and authorize request and marshal response values and errors.