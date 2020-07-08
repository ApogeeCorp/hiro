module github.com/ModelRocket/hiro

go 1.14

// replace github.com/ModelRocket/oauth => ../oauth

replace github.com/a8m/rql => github.com/ModelRocket/rql v1.2.1-dev.1

require (
	github.com/ModelRocket/oauth v1.0.0-dev.2
	github.com/a8m/rql v1.2.0
	github.com/blang/semver/v4 v4.0.0
	github.com/caarlos0/env v3.5.0+incompatible
	github.com/caarlos0/env/v6 v6.3.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-openapi/errors v0.19.6
	github.com/go-openapi/loads v0.19.5
	github.com/go-openapi/strfmt v0.19.5
	github.com/go-openapi/swag v0.19.9
	github.com/go-openapi/validate v0.19.10
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.7.4
	github.com/jmoiron/sqlx v1.2.0
	github.com/lib/pq v1.7.0
	github.com/mitchellh/mapstructure v1.3.2
	github.com/mr-tron/base58 v1.2.0
	github.com/rubenv/sql-migrate v0.0.0-20200616145509-8d140a17f351
	github.com/sirupsen/logrus v1.6.0
	github.com/thoas/go-funk v0.7.0
	github.com/ulule/deepcopier v0.0.0-20200430083143-45decc6639b6
	github.com/urfave/cli/v2 v2.2.0
	gopkg.in/yaml.v2 v2.3.0
)
