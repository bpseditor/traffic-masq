# rs-wgobfs reference implementation

Vendored from the local `../rust/rs-wgobfs` source tree, version 0.6.2.
Upstream: https://github.com/infinet/rs-wgobfs
The local snapshot includes forwarding and logging changes; it is not claimed
to be an unmodified upstream release. Cargo.lock is copied unchanged. The bundled main loop uses initialized
receive buffers and reserves padding/alignment capacity before receiving, avoiding
uninitialized byte slices and an oversized-datagram split panic. Other source
files retain the local snapshot. License: MIT OR Apache-2.0 (see source copyright notices).

This independent Cargo package is excluded from the main workspace to preserve
its dependency lockfile and upstream formatting. It is a test reference, not a
runtime dependency of traffic-masqd. `packaging/test-namespaces.sh` builds it
without privilege and passes the executable path to the isolated VPN tests.
Set `RS_WGOBFS_BINARY` to override the bundled reference.
