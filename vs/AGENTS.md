# AGENTS.md

## Project notes (learned during sessions -- agent sessions will add to this and keep it up to date)

- Tests can use the in-memory DB in `src/db/db_fake.rs` by importing `crate::db::FakeDb`. The module is private, but `src/db/mod.rs` re-exports it under `#[cfg(test)]`.
- ZPR addresses in this repo are IPv6 and should use the prefix `fd5a:5052`.
- `ActorMgr` lives in `src/actor_mgr.rs` and exercises `ActorRepo` + `NodeRepo`. The `add_magic_adapter` method is slated for removal and should not be tested.
- `ActorRepo` and `NodeRepo` operate on Redis-style keys; `FakeDb` is the test backend implementing `DbConnection`.
- `uri_for_service` builds auth service URIs like `zpr-oauthrsa://[fd5a:5052::1]:4000` and expects exactly one `Scope` with a `port`.
- Policy types (e.g., `Scope`, `ServiceType`) come from `zpr-common` (`zpr::policy_types`).

## How tests are structured here

- Unit tests commonly live at the bottom of their module files under `#[cfg(test)]` and use `#[tokio::test]` for async.
- Example usage of building `Actor` values with attributes is in `src/db/actor.rs` and `src/db/node.rs` tests.
