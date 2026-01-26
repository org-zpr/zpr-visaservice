# AGENTS.md

## Overview

This is the Visa Service. Written in rust and part of a larger project called ZPR. The core function
is to check network packets to see if they are allowed according to a policy, and if so issue a "visa".

This uses REDIS to store state.

This makes use of two other projects:
- libeval found in `../libeval`
- zpr-common which is in a separate repository. See `Cargo.toml` for details.


## How tests are structured here

- Unit tests commonly live at the bottom of their module files under `#[cfg(test)]` and use `#[tokio::test]` for async.
- Example usage of building `Actor` values with attributes is in `src/db/actor.rs` and `src/db/node.rs` tests.


## Project notes (learned during sessions -- agents add to this and keep it up to date)

- Tests can use the in-memory DB in `src/db/db_fake.rs` by importing `crate::db::FakeDb`. The module is private, but `src/db/mod.rs` re-exports it under `#[cfg(test)]`.
- ZPR addresses in this repo are IPv6 and should use the prefix `fd5a:5052`.
- `ActorMgr` lives in `src/actor_mgr.rs` and exercises `ActorRepo` + `NodeRepo`. The `add_magic_adapter` method is slated for removal and should not be tested.
- `ActorRepo` and `NodeRepo` operate on Redis-style keys; `FakeDb` is the test backend implementing `DbConnection`.
- Policy types (e.g., `Scope`, `ServiceType`) come from `zpr-common` (`zpr::policy_types`).

