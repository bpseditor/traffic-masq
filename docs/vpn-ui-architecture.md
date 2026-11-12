# VPN and Route: current architecture and UI contract

This document describes the existing daemon boundaries used by the VPN UI.
Moving a control between screens does not change its API or execution model.

## Dependencies and ownership

| Resource | Dependencies | Owner and application path |
| --- | --- | --- |
| Saved WireGuard profile | Profile store, valid profile contents | VPN library; import/delete apply immediately |
| Standalone tunnel | Enabled VPN, saved profile, available owned `tm-wg0` | `VpnManager`; `VpnActivate` / `VpnDeactivate` apply immediately |
| Standalone traffic policy | Enabled VPN, global uplink, managed Output IPv4 subnets, externally managed forwarding; VPN mode additionally needs a healthy standalone interface | `VpnPolicyManager`; immediate Direct/VPN override, separate from router drafts |
| Global VPN chain | Enabled VPN, physical uplink, saved profiles; LAN traffic needs explicit forwarding rules | Router coordinator; shared draft, plan, apply, confirmation, rollback |
| Router's own traffic through VPN | Configured global chain and `route_host_traffic` | Router coordinator; exit policy includes kill switch and IPv6 egress blocking |
| VPN enabled setting | VPN control plane; disabling requires no saved chain, Direct effective policy, and no standalone active record | Persisted subsystem availability; not a disconnect-all operation |

Implementation references:

- [Control API](../src/api/control/vpn.rs), including profile-reference checks,
  disabling prerequisites and policy coexistence guards.
- [VPN manager](../src/vpn/manager.rs), including ownership evidence,
  activation intents, per-interface state and recovery.
- [Chain derivation](../src/core/router.rs) and
  [chain execution](../src/core/router_subsystems/vpn_chain.rs).
- [Standalone policy derivation](../src/core/vpn_policy_manager.rs).
- [Router configuration validation](../src/config/mod.rs).
- [Request admission and recovery gates](../src/api/control/dispatch.rs).

The standalone tunnel uses `tm-wg0`. Chain interfaces use `tm-wg-<index>`;
per-hop managers keep distinct durable ownership records. The same profile
library supplies both paths. A profile is configuration, not a unique runtime
connection. Standalone status is not an inventory of chain interfaces.

There is one ordered global chain, with at most eight hops. The first hop is
closest to the physical uplink. Relay hops route subsequent tunnels through
preceding hops; the exit hop applies protected-subnet policy and the kill switch.
The chain editor preserves explicit forwarding rules. Uplink and chain configuration
do not add forwarding or NAT permissions; configure those in Internet sharing.
For chain traffic, each sharing rule owns its NAT choice: No NAT preserves the
client source address. Enabling router host traffic adds NAT only for locally
generated packets and does not override a sharing rule. Chain health participates
in router readiness even when forwarding itself is healthy. External uplinks
must be unmanaged Input interfaces; DHCP uplinks require managed Input interfaces
with an enabled DHCP client. Validation remains authoritative in the daemon.

The route model stores destination, gateway, output interface, table and metric.
It does not associate routes with profile names or expose named selectable chains.
The standalone policy derives protected subnets from managed Output interfaces;
it is not an arbitrary per-flow traffic selector. This standalone policy overlays
forwarding managed outside traffic-masq. It does not enable IPv4 forwarding or
create direct-mode NAT rules, and cannot coexist with daemon-managed explicit
forwarding in VPN mode.

## Guarantees preserved by the UI

1. Enter on the profile list and the Connect/Disconnect button operate directly
   on the selected connection. Open profile is a separate details action and does
   not activate it. The card pins its name, so list
   refreshes cannot silently retarget profile actions or deletion confirmation.
2. Standalone connect/disconnect only operates on `tm-wg0`. Selecting another
   profile never implicitly disconnects or replaces the active profile. Connecting
   enables a disabled subsystem through SetVpnEnabled, reads VpnStatus, then calls
   VpnActivate only if no connection is active. Failed or uncertain enable/status
   results stop this sequence. There is no automatic compensation or mutation retry.
   Chain membership does not redirect or block connection: per-hop managers own
   separate interfaces. The daemon remains responsible for resource conflicts.
3. Chain edits continue through the existing Uplink / VPN editor and shared Route
   draft. The existing plan, confirmation deadline, rollback and recovery flow
   remain in force. Navigating from a profile to Route preserves a staged draft.
4. Import and deletion retain daemon validation and reference protection.
   Referenced saved-chain profiles cannot be replaced/deleted through the API;
   standalone active-profile protection remains in the manager. The UI also
   prevents deletion of a profile referenced by its unapplied local Route draft.
   Deletion still requires confirmation of the pinned original name.
5. Standalone policy stays an immediate operation, even though its entry point
   is now in Route. It is labelled accordingly and is unavailable when a saved
   global chain exists. The API remains responsible for coexistence and recovery
   gates; the TUI does not combine policy calls into a router transaction.
   Direct VPN mutations require administrator authorization, pass shared network
   admission/execution gates, and are blocked by pending interface/router
   transactions or unresolved recovery state.
6. VPN settings retain the daemon's disabling prerequisites. Disabling does not
   delete saved profiles. Production startup builds the profile control plane
   while disabled, so the library remains available; an unavailable runtime or
   failed read is displayed as unavailable rather than an empty library.
7. Basic list refresh reads VPN availability, profiles and runtime status without
   querying Route. Saved-chain usage is fetched only for profile details, and is
   never a prerequisite for connection. Reads are separate observations, not an
   atomic network snapshot. Cancelling a background refresh for user input keeps
   the previous observation; completed reads replace it together, without clearing
   connection availability midway through a refresh. Failed reads
   preserve useful partial data but invalidate current standalone status and saved
   chain usage. An uncertain connect/disconnect result requires a successful status
   refresh before another standalone mutation. Selection survives refresh by name.
8. Saved chain membership, unapplied draft membership, and observed standalone
   interface state have distinct labels. Interface up does not prove a WireGuard
   handshake, working connectivity, or enforced traffic protection. Chain health
   belongs to Route; profile rows never infer it from saved configuration.
9. Profile cards and lists use only API summaries. Opening a profile does not read
   or display private keys. Local-file import retains its existing secret handling.

## Limits of these guarantees

The UI's reference and freshness checks are advisory between requests; the daemon
owns validation and mutation serialization. Another client can change configuration
between observations. In particular, `VpnDeactivate` has no expected-profile
argument: a different client's replacement of the standalone tunnel between a
status read and disconnect is not atomically excluded by the UI. An unavailable
saved-chain read cannot establish non-use.
A local draft exists only in this TUI and is not known to other clients.

Standalone operations do not gain a commit timer by moving their controls. Their
existing persistence, compensation and ownership-recovery mechanisms remain in
place. A failed rollback or ambiguous persistence outcome is not reported as
successful recovery. These UI changes do not provide an atomic transaction spanning
profile import, standalone activation, policy changes and router changes.

## Manual profile creation

The VPN library's Create action opens a local editor for a complete WireGuard
profile: name, private key, interface address, peer public key, endpoint and
allowed IPs. The type selector chooses WireGuard or WireGuard + wgobfs; the latter
requires forwarding IP, port and password. Save uses the existing
`VpnImportProfile` request and daemon validation/reference protection. It does not
enable VPN or activate a tunnel. Incomplete forms remain local until saved;
cancelling discards them. Private keys and forwarding passwords are masked and
held in zeroizing editor storage. Import from files remains available separately.

## Configuration import and editing

Create retains individual fields and offers Local file and Paste config. Paths
refer to the TUI machine. The full-text editor supports multiline paste, Enter
for a newline, arrows/Home/End for navigation and Tab to leave the editor.
Open profile → Edit config reads the original configuration through an
administrator-only API. Saving uses existing validation and atomic replacement;
profiles referenced by active or saved router intent remain protected.

## Standalone autoconnect

VPN settings has a separate autoconnect area. Select a library profile before
enabling it. Settings persist in vpn-autoconnect.json in the daemon state
directory. Autoconnect is off by default, with five attempts and no direct
fallback. The limit is configurable from 1 to 20. Changing settings or restarting
the daemon resets the retry budget.

The daemon checks every 15 seconds independently of Wi-Fi scans. VPN must be
enabled and no saved chain may be configured. Tentative activation uses the
router transaction coordinator. All peers must have a handshake no older than
180 seconds before automatic commit. Runtime persistent keepalive is enabled
at most every 25 seconds, preserving shorter configured intervals, to initiate
handshakes without application traffic. Saved profile bytes are unchanged.
An existing tunnel uses WireGuard's handshake retransmissions during each retry
window rather than repeated interface destruction.

Unsuccessful tentative activations roll back. After exhaustion, the default
leaves the prior state alone. Optional direct fallback disconnects the tunnel
and switches policy to Direct in one transaction, through the normal mutation
and recovery gates. Chains and another manually selected active profile are
not replaced. Disable autoconnect before intentionally leaving its profile
disconnected.

## Transport path observation

Open profile displays active endpoints with gateway, device and routing table
from a kernel destination lookup over rtnetlink. Refresh updates this view.
For wgobfs the endpoint is the external forwarding server. An endpoint resolving
into its own tunnel is flagged. IPv6 lookup is explicitly unavailable.

This does not install an extra host route or pin a gateway: existing rules and
routes determine egress. A physical default route may already provide the same
path as an endpoint /32. This does not remedy the separately documented missing
relay-hop WireGuard fwmark support.

Live-test observation: the SSH test host's kernel ignores IFLA_IFALIAS included
in WireGuard RTM_NEWLINK, although setting an alias afterward works. The existing
launch-marker crash-cleanup assumption therefore remains a separate limitation
on that host. The handshake test uses a disposable network namespace and does
not claim to validate launch-marker recovery.
