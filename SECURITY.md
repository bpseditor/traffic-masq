# Security

Send vulnerability reports to `ai_norisu@proton.me`. Include the commit,
configuration, steps to reproduce the problem and its likely impact. Remove
passwords, session tokens, private keys and unrelated host details before
sending a report or opening an issue.

The project is under development. There is no maintained stable release series
or guaranteed response time yet.

## Access

The daemon runs as root. File permissions control access to its Unix socket,
and API changes require an administrator session. Only a local root connection
can set the initial password. Optional remote access uses TLS; restrict who can
reach the API before exposing it to an untrusted network.

The daemon records which network resources it owns. Existing addresses, routes,
firewall objects and processes must not be adopted or deleted without an
ownership record.

## Rollback and recovery

The [connectivity change contract](docs/change-safety.md) defines shared admission,
confirmation, recovery ordering and the failure-verification matrix for changes.

The daemon runs the confirmation timer. Disconnecting the client does not stop
an accepted operation. On normal shutdown, the daemon stops admitting operations
and waits up to 30 seconds for accepted operations. It then cancels remaining
tasks and retains unresolved recovery journals. Pending-change cleanup follows;
in-flight storage and runtime work retains its reservations until it finishes.

Router transactions save a private snapshot before making changes. After a
restart, the daemon restores an uncommitted snapshot unless a matching commit
token was saved atomically. Startup remains blocked when the daemon cannot
safely read or prove the persisted recovery evidence. If the journal is
understood but rollback itself fails, the daemon can keep the control plane
available in `RollbackFailed` while retaining the record for diagnosis and an
explicit retry.

`runtime-overrides.json` writes schema version 5 and reads versions 4 and 5.
Version 5 adds committed standalone VPN selection. Older binaries cannot read
newly saved version 5 records; back up state before upgrading and restore a
coherent compatible backup before downgrading. Router journals write version 4
and read versions 2, 3 and 4. Version 4 captures owned sharing routes, tagged
policy rules and interface names for restoration. Older readers reject version 4.
The sharing nftables ownership marker is now v2 (v1 is read for migration), so
older binaries also refuse the new runtime table. Before downgrading, finish all
transactions and remove sharing and port forwards with the newer daemon; preserve foreign VPN state.
Interface journals remain version 3 and provisioning secret journals remain version 2. Never downgrade with unresolved transactions.
These independent schemas must not be edited by hand. If recovery
fails, keep `router-transaction.json` and the state directory. Deleting them to
get past the error also removes information needed for recovery.

Interface changes save snapshots too. Startup restores unconfirmed changes,
including changes to previously unmanaged interfaces, before applying committed
configuration.

Wi-Fi configuration, AP/STA provisioning and profile activation, and live
operator deactivation use commit-confirm. Editing an absent adapter instead
saves durable intent after verified cleanup, without a confirmation timer.
DHCP client/server configuration and disable, and live AP/client passphrase
updates require interface confirmation. Standalone VPN enable/disable,
connection and policy changes require router confirmation. DHCP lease refresh,
Wi-Fi scan/reconnect/reload, station deauthentication and profile-library edits
remain immediate.
Their runtime effects are protected by write-ahead ownership records: DHCP
leases record the route policy under which they were applied, Wi-Fi daemon
records are namespaced by process kind and written before launch, and WireGuard
activation records a launch marker before link configuration. Startup recovery
compares those proofs with committed intent and refuses to delete state whose
ownership cannot be verified. Legacy Wi-Fi AP/client ownership files are
validated by their recorded config path before migration into separate `wifi/ap`
and `wifi/client` namespaces.

Rollback cannot run while the daemon is stopped or killed; recovery resumes
when it starts again. Test recovery on the kernel, init system and hardware you
plan to use.

### Operator recovery boundary

Recovery heals automatically only when the daemon has an independent proof that
no rollback data is still needed. A matching committed router token or an exact
recovery receipt can therefore retire stale metadata even when the full journal
schema is no longer readable. Cleanup failures and transient interface-journal
store I/O are retried. A corrupt journal is never treated as proof by itself.

Manual intervention is required when the daemon cannot prove whether an
interrupted change committed, when journal revisions contradict committed state,
when route ownership is ambiguous, or when the recovery store has a structural
or permission error. In those cases preserve the complete state directory first.
Check the stable `recovery_code` first, then `invariant`, `journal` or `path`,
`operation`, `metadata_safe_to_remove`, and `operator_action`; each fatal code
links to one matching procedure in the
[operator recovery runbook](docs/recovery.md). Do not delete or hand-edit an
unresolved router or provisioning journal merely to make startup continue.

Automatic rollback is bounded to three attempts, 60 seconds per attempt and
180 seconds per cycle. Exhaustion or a non-retryable failure stops the cycle;
device events do not restart it. Explicit rollback retry starts a new cycle
only after the previous one has stopped. Daemon startup rechecks interface
journals in a fresh cycle, while router
recovery retains its explicit retry policy. Cancellation preserves the journal
and recovery guard until compensation completes. See
[bounded recovery](docs/recovery.md#bounded-automatic-recovery).

A corrupt per-interface journal is scoped to that interface. Repair or restore
that interface's journal while leaving the daemon and unaffected interfaces
running. Router rollback failures and foreign-route conflicts similarly keep the
control plane available so the pending transaction can be inspected and an
explicit rollback retried without deleting recovery evidence.

Virtual AP ownership records in `wifi-concurrent/*.json` accept legacy
`parent`/`mac` records and records with an optional `created` receipt. The receipt
contains the kernel NEW_INTERFACE response's wireless-device ID, PHY and actual
MAC, bound to `/proc/sys/kernel/random/boot_id`. It permits removal of that exact
object when a driver ignored the requested random MAC. It does not authorize
normal use with a mismatching MAC. Older readers reject receipt-bearing records;
complete AP cleanup with a compatible daemon before downgrading. Legacy conflicts
are never adopted from their current name or MAC. A crash or failed receipt write
between creation and durable receipt publication can still require operator
repair; preserve all evidence in that case.
