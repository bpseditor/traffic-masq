# Working on traffic-masq

This file applies to the whole repository. traffic-masq is a Linux IPv4 router,
Wi-Fi and WireGuard gateway with a Rust daemon and a separate terminal client.
An incorrect change can sever management access or destroy recovery evidence.
Preserve ownership, commit-confirm and durable recovery as part of correctness.

## Before changing code

- Inspect `git status --short` and the relevant diff. Preserve existing user work,
  including untracked files; do not reset, clean, stash or rewrite unrelated work.
- Read the implementation, its callers and nearby tests before choosing a layer.
  Keep changes focused; avoid unrelated refactors, formatting and dependency updates.
- Use [architecture](docs/architecture.md) for boundaries and lock ordering.
  Before changing any network writer, persistence, cancellation or recovery path,
  read [the connectivity contract](docs/change-safety.md). It includes background
  reconciliation, DHCP callbacks, autoconnect and supervisor repair.
- For TUI work, read [the TUI guide](crates/tui/src/tui/README.md); for VPN/Route
  work, also consult [the VPN UI guide](docs/vpn-ui-architecture.md).
- Documentation can lag implementation, especially descriptions of immediate
  versus confirmed DHCP/VPN operations. Check `Request::policy()`, the production
  control handler and coordinator, their tests, and `docs/change-safety.md`.
  Identify inconsistencies explicitly; do not recreate obsolete behavior from
  a README or silently weaken the connectivity contract to match a shortcut.
- Continue routine edits and local verification within the requested scope.
  Keep host administration, physical testing and external publishing separate
  from ordinary development; do not infer their authorization from a code task.
- Follow [the contribution guide](CONTRIBUTING.md) for editorial changes, test
  infrastructure and architectural moves. Preserve accepted contributor intent
  and surface conflicts for maintainer review. Keep architecture entry points
  current in [architecture decisions](docs/architecture-decisions.md).

## Repository map and dependency boundaries

| Location | Responsibility |
| --- | --- |
| `src/bin/traffic-masqd.rs`, `src/app/` | Daemon CLI, runtime wiring, startup/recovery, convergence, shutdown, installation and init integration |
| `src/api/` | HTTP/REST and typed control adapters, authorization, operation admission and dispatch |
| `src/core/` | Desired state, resource ownership, plans, interface/router transactions, recovery and VPN policy/chain orchestration |
| `src/config/`, `src/state/` | File configuration, resolution, durable overrides and private storage |
| `src/dhcp/`, `src/wifi/`, `src/vpn/` | Runtime services, supervisors, credentials, profiles and ownership recovery |
| `src/firewall/`, `src/command.rs` | Daemon nftables adapter and bounded subprocess execution |
| `crates/protocol/` | Wire DTOs, request/response envelopes, exhaustive request policy and pure shared validation |
| `crates/api-client/` | Unix-socket HTTP, verified HTTPS, authentication and typed client transport |
| `crates/tui/` | `traffic-masq` binary, terminal UI and read-only direct mode |
| `crates/netlink/`, `crates/dataplane/` | Kernel networking; forwarding/nftables models, plans and reconciliation |
| `crates/dhcp-core/`, `crates/wireguard/` | Pure DHCP packets/leases/state machines; WireGuard parsing, kernel provider and obfuscation transport |
| `crates/atomic-file/`, `crates/host-observation/` | Durable file primitives; shared read-only host/init/conflict observation |
| `tests/`, `src/test_support.rs` | Integration suites and reusable simulated OS/process providers |
| `formal/` | Lean transaction model, proofs and reviewed correspondence to Rust |
| `packaging/`, `.github/` | Installation/release scripts, isolated test runners and CI |

- Keep the TUI independent of the root daemon crate. Shared DTOs and pure
  validation belong in `protocol`; transports belong in `api-client`.
  Convert DTOs to daemon configuration at the control boundary.
- Keep netlink, dataplane, DHCP core and host observation independent of daemon
  orchestration. DHCP core has no sockets, stores or supervisors. The daemon
  supplies the bounded `nft` executor to dataplane.
- `traffic-masqd` belongs to the root package; `traffic-masq` belongs to
  `traffic-masq-tui`. Both use explicit binary declarations. Do not recreate
  a TUI binary under the root `src/bin/`.
- Extend existing provider traits, coordinators and shared storage helpers.
  Do not add a second implementation of ownership, retries or rollback in an
  API handler, UI screen or transport adapter.

## Build and verification

Run commands from the repository root unless stated otherwise. Use the pinned
`rust-toolchain.toml` (currently Rust 1.95.0), not an arbitrary newer toolchain.
Linux and a C compiler are required; some targets also need CMake. Runtime/test
packages are listed in [usage](docs/usage.md) and the
[CI setup action](.github/actions/setup-rust/action.yml).

Cargo's default members are the daemon and TUI. A plain `cargo test` is not a
complete workspace test pass. Use `--locked`; update manifests and lockfiles
together only when dependency changes are part of the task.

```sh
# Fast, targeted iteration: choose the affected package/target and test filter.
cargo test --locked -p traffic-masq --lib core::transaction
cargo test --locked -p traffic-masq-tui
cargo test --locked -p traffic-masq --test http_api

# Standard Rust validation, matching .github/workflows/ci.yml.
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo doc --locked --workspace --no-deps

# Build both executables.
cargo build --release --locked --bins
```

Choose checks by the affected behavior. Run targeted tests while iterating and
the standard Rust checks for code changes before handoff where the environment
permits. Documentation-only edits need link/path and diff checks, not a full
network test run. Report unavailable tools and pre-existing failures accurately;
do not alter unrelated work or weaken tests to make a check green.

Additional checks:

| Change | Verification |
| --- | --- |
| Transaction phases, ordering, cancellation or recovery semantics | Review `formal/README.md`, model/proofs and Rust correspondence; run `lake build` from `formal/`, plus the contract's applicable Rust fault/concurrency tests |
| Kernel networking, routing, DHCP or VPN adapters | Run affected namespace suites through the runner below; inspect nearby ignored kernel tests for additional coverage |
| Packaging, install/update scripts or `gitcompile.sh` | `sh packaging/smoke-test.sh` (uses temporary staging and fake binaries) |
| GitHub Actions | `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`, matching current CI |
| TUI interaction/layout | Affected `traffic-masq-tui` tests, including input, rendering and hit targets |

### Network tests and host isolation

```sh
# All allowlisted namespace integration suites; builds as the current user.
sh packaging/test-namespaces.sh

# When unprivileged namespaces are unavailable and sudo is already available.
sh packaging/test-namespaces.sh --sudo

# Example of selecting only affected suites.
sh packaging/test-namespaces.sh --sudo vpn_wireguard_namespace vpn_policy_namespace
```

- Build without root. The runner executes compiled tests inside private
  mount/network/PID namespaces and supports an explicit suite allowlist.
  Never substitute `sudo cargo test` or a workspace-wide `-- --ignored` run.
- Ordinary workspace tests leave privileged and physical tests ignored.
  The namespace runner does not cover every ignored unit/kernel test. Inspect
  each additional test's isolation and prerequisites before selecting it by name;
  do not run embedded `*_kernel_test.py` helpers directly on the host.
- Physical Wi-Fi, live VPN endpoints and the Raspberry Pi testbench require an
  explicit request and their documented setup. Do not auto-select a real adapter,
  contact a testbench or use discovered credentials during routine development.
- Do not start/install/reset the daemon, change host routes/firewall/sysctls,
  stop network managers or modify live state just to validate a patch.
  If isolated checks cannot run, report the coverage gap.
- `gitcompile.sh` can push branches or upload a working-tree snapshot, including
  untracked files. It is not a local build shortcut. Use it only within an
  explicitly authorized remote build/publish task; see [release docs](docs/release.md).

## Network mutation and recovery invariants

The full acceptance matrix is in [docs/change-safety.md](docs/change-safety.md).
The following rules apply to foreground and background writers alike:

1. **One admission policy.** Every request selects authorization, mutation kind,
   recovery scope, idle-interface requirements and deadlines in
   `crates/protocol/src/request_policy.rs`. REST and typed control share it.
   Do not introduce transport-specific bypasses. Preview/status paths remain
   observational and available during pending work or recovery.
2. **Validate under ownership.** Validate intent and risk consent before effects;
   recheck applicable revisions, preview fingerprints and resource assumptions
   under the mutation reservation. A preview is not a lease. Distinguish an
   absent device from failed/unknown observation before accepting offline edits.
3. **Evidence before effects.** Establish durable snapshots, a rollback-only owner
   and cancellation guards before runtime mutation. Apply success and risk consent
   are not commit. Only the matching token persisted atomically with intent and
   revision proves confirmation; stale tokens cannot affect later transactions.
4. **Daemon-owned lifetime.** Disconnects do not cancel accepted operations.
   The monotonic deadline governs commit admission; the displayed Unix expiry
   only describes the confirmation window, not a restoration deadline. After an
   uncertain response, clients inspect current/pending state before another
   mutation; never automatically replay a write.
5. **Shared runtime state and locks.** Use the runtime's existing `RecoveryState`,
   mutation gate, interface lanes and per-PHY locks. Standalone test constructors
   must not introduce independent gates into production. Interface transactions
   must leave convergence able to execute while awaiting it. Queued workers
   re-read intent after admission. Follow the architecture's lock-order table;
   recovery must not wait for a transaction lock while holding the credential
   writer reservation (the existing `try_lock` skip is intentional).
6. **Cancellation retains ownership.** Blocking storage/credential/kernel workers
   can outlive their async caller and must retain reservations until completion.
   Interface cancellation hands compensation to an owned task; router apply/repair
   cancellation retains inspectable rollback-only recovery for explicit retry.
   Shutdown must preserve unresolved journals and drain accepted effects.
7. **Uncertain persistence is not rollback proof.** Use `crates/atomic-file` for
   atomic replacement, file/directory sync and durable deletion. Distinguish
   failure before publication, proven compensation and indeterminate publication.
   Resolve independent commit proof before rollback. Preserve network versus
   settings-only fences; never restore stale in-memory intent over an uncertain
   durable commit.
8. **Complete recovery before retirement.** Restore journaled secrets before
   restarting consumers, attempt independent restoration hooks and collect all
   failures. Keep router stage ordering in the coordinator (`Stage::ALL`). Retain
   evidence on incomplete restoration; do not repeat destructive rollback merely
   because journal cleanup failed. Preserve bounded retry/stopped-cycle behavior;
   device events must not reset recovery budgets.
9. **Preserve foreign resources.** Revalidate ownership of links, addresses,
   routes, firewall objects and processes before changing or removing them.
   Names, PIDs and ifindices alone do not establish ownership across reuse.
   Preserve unresolved/corrupt journals and fence their scope; never delete or
   hand-edit evidence to suppress a recovery failure.

Offline interface and router saves have different ordering: interface cleanup
and fresh absence proof precede durable commit; offline router intent commits
before removal-only cleanup. Router cleanup failure leaves the newly saved
intent authoritative and must be reported separately. Follow the runbook rather
than treating both paths as a generic save.

For VPN protection, preserve the kill switch during failed restoration, restore
previous protection before rebuilding a tunnel, and rebind owned policy routes
when a restored interface receives a new ifindex. A chain/uplink does not grant
forwarding or NAT permissions; explicit sharing rules own those decisions.

## Security and persistence

- Keep server-side authorization authoritative. Initial password setup is local
  root only; HTTPS verifies certificate trust and hostname. Do not add an insecure
  TLS option to work around tests or connection problems.
- Never log request payloads or expose passwords, session tokens, Wi-Fi secrets,
  WireGuard private keys or derived obfuscation keys in debug output, fixtures,
  reports or commits. Use redacted summaries and existing zeroizing secret types;
  preserve cleanup on error and cancellation as well as normal return.
- Reuse private-store checks: ownership, restrictive permissions, rejection of
  unexpected file types/symlinks, atomic writes and durable directory creation.
  Session storage uses private directories (`0700`) and files (`0600`), with
  endpoint/CA isolation. Do not weaken these checks for convenience.
- Persisted schema changes need explicit supported-reader and upgrade/downgrade
  behavior, restart tests and updates to [SECURITY.md](SECURITY.md) and
  [the recovery runbook](docs/recovery.md). Unsupported recovery evidence must
  remain recoverable, not be silently discarded or defaulted to empty state.
- Use bounded subprocess execution at the existing adapter boundary. Preserve
  time/output limits and child termination/reaping. WireGuard configuration hooks
  such as `PreUp`/`PostUp` are not executable application input.

## TUI behavior to preserve

- Direct mode is read-only; daemon operations must be gated in navigation and
  action handlers. Daemon validation remains authoritative even with UI validation.
- Keep saved intent, local drafts and observed runtime separate. Background
  refresh must preserve drafts and selection by stable identity. Unavailable or
  stale observations are not empty lists, absent devices or successful recovery.
- Keep complete-plan review and daemon-owned confirmation flows. A failed request
  or elapsed timer cannot be displayed as verified rollback. Pin destructive
  confirmation targets so refresh cannot change the resource being acted on.
- Use typed actions and the shared confirmation/input helpers. Text editing uses
  grapheme positions and terminal-cell widths, not byte indexing. Left/right
  editing must not switch tabs; modal flows must isolate background actions.
- Register mouse targets in the renderer and clip them to the visible viewport.
  Test keyboard and mouse behavior together, including scrolling, resize and the
  below-80x24 fallback. Preserve accessible pending commit/rollback controls.
- When adding a screen, update its section mapping, help, rendering, keyboard and
  mouse dispatch together. Use `ratatui::backend::TestBackend` for offline tests;
  do not require a live daemon or terminal for ordinary UI coverage.

## Tests, documentation and handoff

- Follow nearby `#[cfg(test)] mod tests` / `tests.rs` conventions. Reuse providers
  in `src/test_support.rs` and fixtures in `tests/support/`. Inject faults at OS
  and storage boundaries while exercising production admission/coordinator paths.
- For affected transaction paths, cover failure, cancellation, concurrency,
  restart and ownership boundaries from the connectivity contract. Assert runtime
  state, durable intent, tokens, fences and journal lifetime; then prove a new
  apply/commit succeeds. Reopen storage in restart tests. Prefer deterministic
  synchronization and Tokio's test clock over arbitrary sleeps.
- Lean proofs describe an abstract protocol; they do not verify Rust, kernel I/O
  or physical connectivity. Simulated providers and namespace tests likewise
  establish different evidence. State which layer was actually verified.
- Update the relevant API/configuration/usage docs and `examples/config.toml`
  when changing user-visible contracts or defaults. Keep this file a navigation
  and invariant guide; detailed schemas, recovery codes and procedures belong
  in their existing reference documents.
- Before handoff, inspect the final diff and run `git diff --check`. Report what
  changed, the checks actually run, and any remaining failures or evidence gaps.
  Do not claim a filtered pass covers the workspace, privileged tests or hardware.
