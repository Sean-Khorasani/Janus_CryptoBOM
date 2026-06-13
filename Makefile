SHELL := /bin/bash

include VERSION.env
FULL_VERSION := $(JANUS_VERSION)+$(JANUS_BUILD_DATE).$(JANUS_BUILD_SEQUENCE)
GO_VERSION_LDFLAGS := -X github.com/janus-cbom/janus/server/internal/version.Version=$(JANUS_VERSION) -X github.com/janus-cbom/janus/server/internal/version.BuildDate=$(JANUS_BUILD_DATE) -X github.com/janus-cbom/janus/server/internal/version.BuildSequence=$(JANUS_BUILD_SEQUENCE) -X github.com/janus-cbom/janus/server/internal/version.APIVersion=$(JANUS_API_VERSION) -X github.com/janus-cbom/janus/server/internal/version.AgentProtocolVersion=$(JANUS_AGENT_PROTOCOL_VERSION)

.PHONY: ui server agent test race bootstrap-check fmt-check lint proto-check build release-linux compose-check linux-gate vuln verify-claims release-evidence interop-lab

ui:
	cd ui && npm ci && VITE_JANUS_VERSION=$(FULL_VERSION) VITE_JANUS_REQUIRED_API_VERSION=$(JANUS_UI_REQUIRED_API_VERSION) npm run build

server:
	cd server && go test -mod=readonly ./... && go build -mod=readonly -trimpath -ldflags '$(GO_VERSION_LDFLAGS)' ./cmd/janus-server

agent:
	cd agent && cargo test --locked --all-targets && JANUS_BUILD_DATE=$(JANUS_BUILD_DATE) JANUS_BUILD_SEQUENCE=$(JANUS_BUILD_SEQUENCE) JANUS_AGENT_PROTOCOL_VERSION=$(JANUS_AGENT_PROTOCOL_VERSION) JANUS_AGENT_MIN_SERVER_VERSION=$(JANUS_AGENT_MIN_SERVER_VERSION) cargo build --locked --release

release-linux: build
	packaging/linux/build-release.sh
	packaging/linux/build-packages.sh --release $(JANUS_BUILD_DATE).$(JANUS_BUILD_SEQUENCE)

test: ui server agent

race:
	cd server && go test -race -count=1 ./...
	cd agent && cargo test -- --test-threads=1

bootstrap-check:
	@test "$$(uname -s)" = Linux || { echo "error: linux-gate requires Linux" >&2; exit 1; }
	@for tool in git go cargo rustfmt npm docker shellcheck protoc python3; do \
		command -v "$$tool" >/dev/null 2>&1 || { echo "error: missing required tool: $$tool" >&2; exit 1; }; \
	done
	@cargo clippy --version >/dev/null 2>&1 || { echo "error: missing required Rust component: clippy" >&2; exit 1; }
	@docker compose version >/dev/null 2>&1 || { echo "error: Docker Compose v2 is required" >&2; exit 1; }
	@for lockfile in server/go.sum agent/Cargo.lock ui/package-lock.json; do \
		test -f "$$lockfile" || { echo "error: missing dependency lockfile: $$lockfile" >&2; exit 1; }; \
	done
	@echo "Linux build prerequisites are available."

fmt-check:
	@files="$$(find server -type f -name '*.go' -print0 | xargs -0 gofmt -l)"; \
	test -z "$$files" || { printf 'error: gofmt required for:\n%s\n' "$$files" >&2; exit 1; }
	cd agent && cargo fmt --check

lint:
	cd server && go vet -mod=readonly ./...
	cd agent && cargo clippy --locked --all-targets -- -D warnings
	find scripts tests -type f -name '*.sh' -print0 | xargs -0 shellcheck

proto-check:
	bash scripts/proto/verify.sh

# WP-025: fail the build if documentation over-claims maturity/certification, or
# if any capability-maturity dimension lacks a current-status declaration.
verify-claims:
	python3 scripts/verify-claims.py

# WP-025: generate a release-evidence bundle (gate outcomes + maturity snapshot).
release-evidence:
	bash scripts/release-evidence.sh

# WP-027: regenerate the interoperability lab report from live policy targets.
interop-lab:
	python3 scripts/interop-lab-report.py

build: ui server agent

compose-check:
	docker compose -f docker-compose.yml config --quiet

vuln:
	@command -v govulncheck >/dev/null 2>&1 || { echo "error: govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)" >&2; exit 1; }
	@command -v cargo-audit >/dev/null 2>&1 || { echo "error: cargo-audit not installed (cargo install cargo-audit --locked)" >&2; exit 1; }
	cd server && govulncheck ./...
	cd agent && cargo audit
	cd ui && npm audit --audit-level=high --production

linux-gate: bootstrap-check fmt-check lint proto-check verify-claims test compose-check
	@echo "Linux build gate passed."
