# Architecture decisions

This record starts with decisions that affect where a contributor finds code.
For a new responsibility move, record the reason, old and new entry points,
the contract that callers rely on, and the test that verifies it.

## Request admission is shared by REST and typed control

Commit `fa8ca74` centralized classification so a new operation makes one
authorization, mutation and recovery decision across transports. Add the
classification in [request policy](../crates/protocol/src/request_policy.rs),
then follow [daemon dispatch](../src/api/control/dispatch.rs) to the handler.
Use [HTTP integration tests](../tests/http_api.rs) for transport behavior and
[control tests](../src/api/control/tests/mod.rs) for admission and effects.

## Compensation lives with the operation it restores

Commit `2fc9c20` moved activation and provisioning compensation out of API
handlers. The API translates requests and outcomes. The
[Wi-Fi activation operation](../src/core/wifi_profile_activation.rs) tracks
changed runtime components, and [router provisioning apply](../src/core/provisioning_apply.rs)
works with the router coordinator. Check activation and rollback through the
[control Wi-Fi tests](../src/api/control/tests/wifi_client.rs) and
[provisioning tests](../src/api/control/tests/provisioning.rs).

## Recovery state belongs to one daemon session

Commit `e770010` replaced process-global bookkeeping with a shared
session-owned [recovery context](../src/core/recovery.rs).
Start at [daemon initialization](../src/app/mod.rs) to follow how the context
reaches coordinators and workers. Volatile locks and retry state stay within
that session. Durable journals retain recovery evidence across restarts.
The [recovery control tests](../src/core/recovery_control/tests.rs) cover the
context, and the [connectivity contract](change-safety.md) describes its
interaction with ownership, mutation and restart.

## Find REST handlers and TUI state by responsibility

Commit `94cbe7d` moved REST handlers out of [the server entry point](../src/api/server.rs)
into [feature modules](../src/api/server/) and split control tests into
[feature suites](../src/api/control/tests/). REST handlers translate transport
input and share admission with typed control. The same refactor grouped
confirmation, DHCP and Wi-Fi UI state in [TUI state](../crates/tui/src/tui/state.rs).
Find the corresponding input and rendering code through the
[TUI file map](../crates/tui/src/tui/README.md#2-directory--component-inventory).

## Explicit cancellation preserves coordinator ownership

`api::operations` tracks cancellation identities; `core::mutation` carries the signal.
Existing coordinators retain compensation. Paired AP defaults are resolved after
explicit/tentative intent in `state::overrides` and `core::desired`.
See [the contract](change-safety.md#runtime-ownership-and-cancellation) and
[architecture](architecture.md#applying-changes) for invariants and entry points.

## Sharing owns its selected forwarding route

`ForwardingConfig::to` now selects routing as well as firewall/NAT permission.
`dataplane::sharing` uses the existing network provider, nft operation reservation
and router coordinator; API/TUI adapters do not write routes. Router journals
capture tagged policy rules/routes and restore interface names after index changes.
The dataplane tests cover ownership, cancellation, drift and restoration;
`router_dataplane_namespace` exercises a foreign full-tunnel rule and verifies
outbound/return traffic, reopened snapshots and preservation of foreign state.

## Virtual AP creation receipts and scoped cleanup

`wifi::concurrent` retains the acknowledged kernel creation identity before
reporting a driver MAC mismatch. Removal verifies the receipt against the current
boot, wireless-device ID, PHY and MAC and targets that wireless-device ID. It
never reconstructs missing proof from an existing same-name device. Legacy random
MAC ownership remains supported; conflicting legacy records remain fenced.
`app::reconcile` reports withdrawn-AP cleanup failures against the parent/AP
scope, allowing unrelated interface transactions to converge and commit.
No transaction phase, confirmation or journal-retirement rule changes.

### Wi-Fi driver profiles

`wifi::driver` selects AP setup behavior from the parent's sysfs `device/driver`
link. Exact `brcmfmac` selects post-creation MAC correction; other identified
drivers retain the standard path. Failed driver observation blocks creation.
The profile selection is centralized so additional driver behavior can be added
without scattering device-name or board-model checks through convergence.
`wifi::concurrent` retains ownership, durable receipts and cleanup; profiles
cannot adopt existing interfaces or bypass those checks. The correction uses
the existing network provider while the new AP is DOWN, after durable creation
proof and identity revalidation, then checks the resulting MAC and wdev.
