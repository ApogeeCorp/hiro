.PHONY: proto
proto:
	protoc -I./api/proto/v1 --experimental_allow_proto3_optional --go_out=./pkg/hiro/pb --go_opt=paths=source_relative \
    --go-grpc_out=./pkg/hiro/pb --go-grpc_opt=paths=source_relative \
    ./api/proto/v1/*.proto

.PHONY: generate
generate:
	go generate ./...