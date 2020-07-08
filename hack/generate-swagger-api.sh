#!/bin/sh
set -eu

swagger flatten \
	-o api/swagger-flat.yaml --format=yaml \
	 api/swagger.yaml

swagger generate model -f api/swagger-flat.yaml \
	-t api -m types -C api/swagger-gen.yaml \
	-n ErrorResponse \
	-n Application \
	-n address \
	-n profile \
	-n User

swagger generate operation -f api/swagger-flat.yaml \
	-t api -a types -C api/swagger-gen.yaml \
	-T api/templates --skip-responses --skip-url-builder \
	-n HelloWorld

# generate the embedde spec file
swagger generate server -f api/swagger-flat.yaml \
	-t api -s server -T api/templates -C api/swagger-gen.yaml \
	--skip-models --skip-operations --exclude-main