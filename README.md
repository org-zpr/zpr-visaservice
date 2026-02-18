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
- `core` - **DEPRECATED** - This is the prototype Visa Service written in Go.
- `vs-conform` - **DEPRECATED** - An old conformance tester for the prototype
  visa service.

Most of the new visa service code depends on the
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
- **Redis** - Required at runtime by `vs`.


## To build

Run `make` to build all Rust crates, or `make test` to run unit
tests.

Individual crates can be built by running `make` in their subdirectory (e.g.
`make -C vs all`).

Note: there is no root `Cargo.toml` workspace. Do not run `cargo build` from
the repository root.


## Release build (prototype vs only)

Run `make release` to produce a release tarball of the visa service tools. This
builds everything, then packages the `vs`, `vs-admin`, and `zpt` binaries into
`build-release/`.


## Admin HTTPS API

The visa service (`vs`) exposes an HTTPS admin API on port 8182 by default.
The `vs-admin` command line tool consumes this API.

See [admin-http-api.txt](admin-http-api.txt) for full endpoint documentation.


<details>
<summary>Deprecated Prototype Visa Service</summary>

### To build (prototype vs)

Run `make build-go` to build.  To run the tests do `make test-go`.

After a successful build the `vservice` binary will be found in
`core/build`.

When compiler is updated you may need to rebuild the pregenerated policy
files used for testing.  Do that with: `make ZPLC=/path/to/zplc pregen`.


### Visa Service Admin API (prototype vs)

This is an HTTPS API for controlling the visa service designed for network
administrators. Access is protected by policy. The default port is TCP/8182 (see
`core/pkg/vservice/constants.go`), and this uses the ZPR contact address of the
adapter in front of the visa service.

The API code is in `core/pkg/vservice/admin.go`.

API returns `application/json`, unless there is an error.

The separate binary `vs-admin` (in the `vs-admin` subdirectory) is a command
line tool which uses the admin interface.


**API Summary**

| METHOD | PATH                               | EXPLAIN                                           |
| ------ | ---------------------------------- | ------------------------------------------------- |
| GET    | `/admin/policies`                  | list policies                                     |
| POST   | `/admin/policy`                    | install a policy                                  |
| GET    | `/admin/policy/{configID}/current` | get the current policy for configuration          |
| GET    | `/admin/visas`                     | list visas                                        |
| DELETE | `/admin/visas/{ID}`                | revoke a visa by its ID                           |
| GET    | `/admin/actors`                    | list connected actors                             |
| DELETE | `/admin/actors/{CN}`               | revoke an actor (and all its visas) by adapter CN |
| GET    | `/admin/services`                  | a service-oriented list of connected actors       |
| POST   | `/admin/revokes`                   | administer the revocation table                   |
| GET    | `/admin/nodes`                     | list nodes                                        |


### Visa Service API (prototype vs)

The main visa service api (for requesting visas and connection control) is a
THRIFT API. This runs on TCP/5002 by default. See `vs.thrift` in the
zpr-vsapi repo for documentation.

### Protocol Buffers (prototype vs)

The compiled protocol buffers are included in source, but if you need to rebuild
them you must install:

```
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

</details>
