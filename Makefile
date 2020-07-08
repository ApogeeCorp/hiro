.PHONY: api-gen
api-gen: ## generate the api type structs
	docker run --rm -v $(PWD)/..:/go/src/github.com/Teralytic \
		-w /go/src/github.com/Teralytic/teralytic \
		--entrypoint hack/generate-swagger-api.sh \
		-e GOPATH=/go \
		quay.io/goswagger/swagger

.PHONY: db
db: ## gereate embedded sql source
	@echo "Generating embedded SQL scripts"
	go generate ./pkg/backend/timescale