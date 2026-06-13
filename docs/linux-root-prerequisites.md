# Linux Root Prerequisites

These commands target the supported Ubuntu 24.04 x86_64 development host.
Run them as `root` or prefix each command with `sudo`.

## Native Build And Test Packages

```bash
apt-get update
apt-get install -y \
  build-essential ca-certificates clang cmake curl git jq make ninja-build rsync \
  openssl pkg-config protobuf-compiler shellcheck strace unzip xz-utils zip \
  libclang-dev libpq-dev libsqlite3-dev libssl-dev \
  postgresql-client-16 softhsm2 opensc
```

Go 1.25.x, Rust 1.96.0, and Node.js 22.x are pinned project toolchains. Install
them from their upstream distributions rather than Ubuntu's older packages.
After installing Rust, add the required components as the development user:

```bash
rustup toolchain install 1.96.0 --component clippy,rustfmt
rustup default 1.96.0
```

## Docker And User Access

Install Docker Engine and Compose v2 from Docker's official Ubuntu repository.
Then allow the development user to access the daemon:

```bash
usermod -aG docker "$DEVELOPMENT_USER"
```

Log out and back in after changing group membership. Docker group membership
grants root-equivalent daemon access; do not add untrusted users.

## Browser Test Dependencies

From the repository, install Chromium and its Linux system dependencies:

```bash
cd ui
npx playwright install --with-deps chromium
```

## Optional Deployment Tooling

Install current `helm` and `kubectl` releases from their official repositories
before running Helm or Kubernetes release gates. These tools are not available
at the required versions from the default Ubuntu repository.

Verify the host after provisioning:

```bash
make bootstrap-check
make linux-gate
```
