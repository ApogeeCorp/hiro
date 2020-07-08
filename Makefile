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

.PHONY: api-docs
api-docs: ## preview the API documentation
	@echo "API docs preview will be running at http://localhost:$(API_DOCS_PORT)"
	@docker run --rm -v $(PWD)/api/:/usr/share/nginx/html/swagger/ \
		-e 'REDOC_OPTIONS=hide-hostname="true" lazy-rendering' \
		-e SPEC_URL=swagger/swagger.yaml \
		-p $(API_DOCS_PORT):80 \
		redocly/redoc