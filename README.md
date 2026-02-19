# visa service

ZPR visa service implementation (under active development).


## Crates / Packages / Libraries

- `vs` - The ZPR Visa Service. Aka "v2vs" -- the "v2" used to differentiate it
  from the "v1", prototype visa service.
- `libeval` - The "evaluator" library used by the `vs` and `zpt`. Includes the
  code that compares a description of network traffic to policy to determine if
  a visa should be issued.
- `zpt` - ZPR Policy Tester is a command line tool for testing how `libeval`
  evaluates policy.
- `vs-admin` - Bare bones administration client for the visa service. Exercises
  the HTTPS admin api of `vs`.
- `admin-api-types` - Library crate for data structures used by `vs` and
  `vs-admin`.
- `integration-test` - Shell-based integration tests. Includes a conformance
  test of the prototype visa service using `vs-conform`, and evaluation tests
  of `libeval` using `zpt`.
- `tools` - Helper scripts, including `zpr-pki` for PKI operations.

Most of the visa service code depends on the
[zpr-common](https://github.com/org-zpr/zpr-common.git) repository, which
defines data structures used in the NODE-VS API and the policy binary format.
This dependency is pulled automatically via git in `Cargo.toml` (see e.g.
`libeval/Cargo.toml`), so no manual setup is required.


## Prerequisites

- **Rust** - Edition 2024 (see individual `Cargo.toml` files). Install via
  [rustup](https://rustup.rs/).
- **Make** - The build is driven by per-crate Makefiles; there is no root
  Cargo workspace.
- **OpenSSL** - Required by `vs` and `libeval` (via the `openssl` crate).
- **Redis/Valkey** - Required at runtime by `vs`.


## To build

Run `make build-rs` to build all Rust crates, or `make test-rs` to run unit
tests.

Individual crates can be built by running `make` in their subdirectory (e.g.
`make -C vs all`).

Note: there is no root `Cargo.toml` workspace. Do not run `cargo build` from
the repository root.


## Release build (prototype vs only)

Run `make release` to produce a release tarball of the older, prototype visa
service. This builds everything (both Rust and Go), then packages the old
vservice and vs-conform binaries into `build-release/`.


## Admin HTTPS API

The visa service (`vs`) exposes an HTTPS admin API on port 8182 by default.
The `vs-admin` command line tool consumes this API.

See [admin-http-api.txt](admin-http-api.txt) for full endpoint documentation.


