# Repository Guidelines

## Project Structure & Module Organization

Janus CryptoBOM is a multi-language monorepo connected by `proto/janus.proto`.

- `agent/`: Rust endpoint agent and interceptor; discovery modules live in `agent/src/discovery/`.
- `server/`: Go control plane, with executables in `server/cmd/` and packages in `server/internal/`.
- `ui/`: React, TypeScript, Vite, and Tailwind dashboard; Playwright scenarios are in `ui/tests/`.
- `tests/`: PowerShell integration suites and scanner fixtures in `tests/testdata/`.
- `policies/`, `config/`, and `plugins/`: profiles, prompt templates, and inventory plugins.
- `deploy/`, `packaging/`, and `dev/native-deployment/`: Kubernetes deployment, release packages, and the manual native deployment sandbox.
- `HSM/` and `scripts/`: SoftHSM support, CI helpers, and service tooling.

Treat `proto/janus.proto` as the canonical agent-server contract. Synchronize protocol changes across Rust and Go.

## Build, Test, and Development Commands

- `make test`: build and test the UI, Go server, and Rust agent.
- `cd ui && npm run dev`: start Vite at `http://127.0.0.1:5173`.
- `cd ui && npx playwright test`: run browser scenarios.
- `cd server && go test ./...`: run Go package tests.
- `cd agent && cargo test`: run Rust tests.
- `msbuild JanusCryptoBOM.msbuild.proj /t:BuildNoTools`: full Windows build.
- `.\scripts\test-e2e-windows.ps1 -SkipBuild`: run Windows end-to-end validation.
- `.\tests\run-all-tests.ps1`: run PowerShell suites; API checks require a running server.

## Coding Style & Naming Conventions

Run `gofmt` on Go changes and `cargo fmt` on Rust changes. Follow existing TypeScript formatting: two-space indentation, semicolons, `PascalCase` React components, and `camelCase` functions/hooks. Use lowercase Go package names and `snake_case` Rust modules. Name Playwright files `feature-name.spec.ts` and PowerShell suites `test-feature.ps1`.

Keep changes scoped to the owning component. Do not hand-edit generated protobuf types.

## Testing Guidelines

Add focused tests beside changed behavior, then run the relevant component command before `make test`. Playwright covers dashboard workflows; `tests/scripts/` covers API, policy, HSM, accessibility, and integration behavior. There is no documented coverage threshold; prioritize regressions involving signing, rollback, policies, and protocols.

## Commit & Pull Request Guidelines

Recent commits use scoped, imperative subjects such as `ui/a11y: added FocusTrap` and `policies: added minimum_confidence field`. Keep commits focused and use a clear subsystem prefix.

Pull requests should explain behavior changes, list verification commands, link issues, and include screenshots for UI changes. Call out schema, protobuf, policy, deployment, or security impacts.

## Security & Configuration

Never commit credentials or signing keys. `JANUS_COMMAND_SIGNING_KEY` is required by the server and agent. Keep active migration disabled unless intentionally testing it, and preserve HMAC verification, path sandboxing, validation, and rollback protections.
