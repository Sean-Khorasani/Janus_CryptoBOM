.PHONY: ui server agent test

ui:
	cd ui && npm install && npm run build

server:
	cd server && go mod tidy && go test ./... && go build ./cmd/janus-server

agent:
	cd agent && cargo test && cargo build --release

test: ui server agent

