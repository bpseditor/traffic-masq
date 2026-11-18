# Contributing to traffic-masq

Documentation corrections, focused fixes and improvements to test fixtures
are welcome as standalone pull requests. For a documentation correction,
point to the confusing passage and explain what the reader needs to know.

## Find the code and tests

| Your change | Start here | Verify with |
| --- | --- | --- |
| Improve operator instructions | [README](README.md) for first setup, [operating guide](docs/usage.md) for procedures, [recovery runbook](docs/recovery.md) for fault handling | Follow the procedure against the current UI or API and check links |
| Fix terminal input, layout or draft handling | [TUI file map](crates/tui/src/tui/README.md#2-directory--component-inventory) and the screen's input and render code | Nearby offline tests in `traffic-masq-tui`, including keyboard and mouse where applicable |
| Change an API request or response | [Protocol policy](crates/protocol/src/request_policy.rs), [daemon dispatch](src/api/control/dispatch.rs) and the [API reference](docs/api.md) | [HTTP integration tests](tests/http_api.rs) and [control tests](src/api/control/tests/mod.rs) |
| Change apply, confirmation or recovery | [Connectivity contract](docs/change-safety.md), [interface transaction](src/core/transaction.rs) or [router coordinator](src/core/router_transaction.rs) | Nearby fault and restart tests, plus [Lean correspondence](formal/README.md#correspondence-with-rust) for changes to transaction ordering |
| Change DHCP packet handling, routes, nftables or WireGuard | [Architecture and package boundaries](docs/architecture.md) | Affected package tests and, for kernel behavior, the [isolated network runner](docs/usage.md#test) |

### Follow a DHCP policy edit

1. The [TUI editor](crates/tui/src/tui/dhcp_client_editor.rs) builds
   `ConfigureDhcpClient` and opens **Pending change** on a successful tentative apply.
2. [Request policy](crates/protocol/src/request_policy.rs) classifies it as an
   interface transaction. The [dispatcher](src/api/control/dispatch.rs)
   routes it to the [DHCP control handler](src/api/control/dhcp_client.rs).
3. The handler validates the prepared input interface and hands off to the
   [interface transaction manager](src/core/transaction.rs). The daemon owns
   the confirmation deadline, persistence and rollback.
4. Run the editor test for navigation and the daemon test for actual admission,
   durable state and rollback.

   ```sh
   cargo test --locked -p traffic-masq-tui route_policy_apply_opens_confirmation_and_can_rollback
   cargo test --locked -p traffic-masq --lib dhcp_route_policy_requires_commit_and_rollback_restores_runtime
   ```

For changes to architectural boundaries, see [architecture decisions](docs/architecture-decisions.md).

## Verify the behavior you changed

Run commands from the repository root with its pinned Rust toolchain. The
[operating guide](docs/usage.md#requirements) lists build prerequisites.
Ordinary development and unit tests require no router, live VPN or host
network configuration changes.

Test the production behavior that should fail when the regression returns.
A fake provider can record observable calls, inject a fault or represent
runtime state. Exercise the actual handler or coordinator before checking
those observations. Give test infrastructure its own tests when it has an
independent contract or a failure could invalidate the suite. For documentation
examples, keep machine-readable identifiers stable and let prose be edited freely.

For Rust changes, run the [workspace checks](README.md#checks) where possible.
For documentation-only changes, check links, examples you edited and
`git diff --check`. State which checks ran and which layers still need verification.

## Keep changes reviewable

- Keep wording, test cleanup and behavior changes independently reviewable.
  Carry forward existing editorial intent and focused contributor fixes.
- Ask for maintainer review before reverting an accepted editorial or test
  infrastructure change. Explain the conflict in the pull request and show
  how the replacement preserves the original purpose.
- Discuss a cross-module responsibility move or a change to a public or
  recovery contract before implementation. Record its reason, new entry points
  and verification in [architecture decisions](docs/architecture-decisions.md).
- Apply these rules to automated changes too. The submitting contributor
  reviews generated changes before posting them. Report broad generated edits
  and obtain human review before merging them.
