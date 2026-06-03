# Changelog

All notable changes to continuity-auth's user-facing surface are
documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Server
versions follow semantic versioning; the wire envelope format carries
its own version tag (`FPL2`) so envelopes can outlive the Clojure
namespaces that signed them.

Earlier feature milestones (0.2.0–0.6.0) ship under the same envelope
contract; they're enumerated in the README "Shipped" section rather
than retroactively backfilled here.

## [Unreleased] — 2026-06-03

Auth becomes a *plugin* under the new `continuity` parent CLI rather
than carrying the parent itself. The dispatcher source and bootstrap
installer moved into the new
[continuity-cli](https://github.com/danieltanfh95/continuity-cli)
repo, where they can serve every continuity-* plugin uniformly. No
on-wire or on-disk changes; the envelope format, HTTP API, and
Datalevin schema are all unchanged.

### Changed (breaking, user-facing CLI)

- **Binary renamed `bin/continuity` → `bin/continuity-auth`.** Invocable
  as `continuity-auth <verb>` (direct) or `continuity auth <verb>`
  (via the continuity-cli parent dispatcher, which discovers
  `continuity-auth` on PATH and spawns it with stdio inherited). The
  internal `bb` task remains `clojure -M:admin` etc.
- **`admin` is now a sub-verb of the auth plugin** rather than a
  top-level dispatcher route. Invocation:
  `continuity auth admin revoke-key …` (via dispatcher) or
  `continuity-auth admin revoke-key …` (direct). The HTTP API and
  HMAC contract are unchanged; only the entry-point shape moves.
- **`install.sh` and `Formula/continuity.rb` deleted.** Bootstrap
  install now lives in
  [continuity-cli](https://github.com/danieltanfh95/continuity-cli).
  The migration path:
  ```sh
  curl -fsSL https://raw.githubusercontent.com/danieltanfh95/continuity-cli/main/install.sh | sh
  continuity install --include auth
  ```
  Or install auth standalone via bbin without the parent dispatcher:
  ```sh
  bbin install https://github.com/danieltanfh95/continuity-auth.git --as continuity-auth
  ```

### Internal (non-user-facing)

- New ns `continuity-auth.client.plugin-dispatch` replaces the deleted
  `continuity-auth.client.dispatch`. Same job (route `--help` /
  `--version` / `admin` / fallthrough to `run-auth`); narrower in
  scope (no plugin-discovery, no install subcommand — those live in
  continuity-cli now).
- `continuity-auth.admin.cli/run-admin` docstring updated to reference
  the new namespace; behaviour unchanged.

### Unchanged (intentional)

- Wire envelope (`FPL2`), HTTP API (`/v1/bootstrap`, `/v1/verify`,
  `/v1/admin/*`), HMAC admin auth, Datalevin schema, IP-HMAC key
  derivation, biscuit token contract, fingerprint signal set.
- Server JVM entry (`clojure -M:run`), test runner
  (`clojure -M:test`), build pipeline, docker-compose.
- Internal Clojure namespaces under `continuity-auth.server.*` and
  `continuity-auth.client.{cli,json}` — only `client.dispatch` was
  renamed (to `client.plugin-dispatch`).
