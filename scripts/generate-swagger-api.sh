#!/bin/sh
set -eu

# generate the embedded spec file
swagger generate server -f api/swagger.yaml \
	-t api -s spec --template=atomic -C api/swagger-gen.yaml \
	--skip-models --skip-operations --exclude-main
