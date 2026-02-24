# AGENTS.md

## Repo Map
Rust workspace with main crate `vs` (visa service) and supporting crates:
`libeval`, `zpt`, `vs-admin`, `admin-api-types`.
(`zpr-common` is in a separate repository.)

## Required Rust Workflow
- After Rust edits: run `cargo build` and fix errors.
- Then run `cargo fmt -- --check` and fix formatting.
- Run `cargo test` when tests exist or are relevant.
- For refactors/renames, search usages across all crates in this workspace.
- If a plan file exists (e.g. `PLAN.md`), follow it exactly unless the user approves scope changes.

## Project Note
- ZPR addresses are IPv6 and must use prefix `fd5a:5052`.
