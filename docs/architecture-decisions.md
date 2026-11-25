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

`api::operations` tracks non-reusable client operation identities. Administrative
cancellation signals in `core::mutation` bypass waiting for admission but never
execute network writes. Interface and router coordinators observe them only at
compensatable apply boundaries; transport disconnection remains independent.
See the [cancellation contract](change-safety.md#runtime-ownership-and-cancellation)
and operation, admission and coordinator cancellation regression tests.

Paired AP defaults are derived in runtime configuration after explicit and tentative
intent, without changing stored schemas or enabling services. Child convergence
verifies virtual-link ownership before mutation. Desired-state and override tests
cover parent withdrawal, explicit child settings and suppression.
