#!/bin/sh
# Build without privilege; run each approved suite in its own isolated environment.
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
use_sudo=false
if [ "${1:-}" = --sudo ]; then
    use_sudo=true
    shift
fi
if [ "$#" -eq 0 ]; then
    set -- netlink_namespace dhcp_namespace dhcp_client_namespace router_namespace \
        router_namespace_negative router_dataplane_namespace \
        vpn_wireguard_namespace vpn_policy_namespace
fi
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
for suite do
    case "$suite" in
        netlink_namespace|dhcp_namespace|dhcp_client_namespace|router_namespace|router_namespace_negative|router_dataplane_namespace|vpn_wireguard_namespace|vpn_policy_namespace) ;;
        *) printf 'Unsupported namespace suite: %s\n' "$suite" >&2; exit 1 ;;
    esac
    printf '%s\n' "$suite" >> "$stage/suites"
done
# Keep the reference implementation independent of the native client. Build it
# without privilege and obtain its actual path from Cargo (also with target overrides).
reference_binary=${RS_WGOBFS_BINARY:-}
if grep -qx vpn_wireguard_namespace "$stage/suites" && [ -z "$reference_binary" ]; then
    cargo build --locked --manifest-path vendor/rs-wgobfs/Cargo.toml \
        --bin rs-wgobfs --message-format=json > "$stage/reference.jsonl"
    reference_binary=$(python3 - "$stage/reference.jsonl" <<'PYREF'
import json
import pathlib
import sys

artifacts = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
print(next(item["executable"] for item in artifacts
           if item.get("reason") == "compiler-artifact"
           and item.get("target", {}).get("name") == "rs-wgobfs"
           and item.get("executable")))
PYREF
    )
fi
if [ -n "$reference_binary" ]; then
    reference_binary=$(realpath "$reference_binary")
    test -x "$reference_binary"
fi
set --
while IFS= read -r suite; do
    set -- "$@" --test "$suite"
done < "$stage/suites"
# Match the workspace feature resolution used by CI's ordinary test pass, so
# selecting namespace targets does not rebuild them with a different feature set.
cargo test --locked --workspace --no-run --message-format=json "$@" > "$stage/build.jsonl"
python3 - "$stage" <<'PY'
import json
import pathlib
import subprocess
import sys

stage = pathlib.Path(sys.argv[1])
requested = stage.joinpath("suites").read_text().splitlines()
artifacts = {}
for line in stage.joinpath("build.jsonl").read_text().splitlines():
    message = json.loads(line)
    if (message.get("reason") == "compiler-artifact"
            and message.get("profile", {}).get("test")
            and "test" in message["target"]["kind"]
            and message.get("executable")):
        artifacts[message["target"]["name"]] = message["executable"]
with stage.joinpath("executables").open("w") as manifest:
    for suite in requested:
        executable = artifacts[suite]  # Missing artifacts must fail the job.
        listing = subprocess.run([executable, "--ignored", "--list"],
                                 check=True, capture_output=True, text=True).stdout
        count = sum(line.endswith(": test") for line in listing.splitlines())
        if not count:
            raise RuntimeError(f"{suite} contains no ignored tests to execute")
        manifest.write(f"{suite}\t{executable}\t{count}\n")
PY
host_netns=$(readlink /proc/self/ns/net)
while IFS="$(printf '\t')" read -r suite executable count; do
    printf 'Running %s (%s ignored tests) in isolated namespaces\n' "$suite" "$count"
    set -- unshare --mount --net --pid --fork --kill-child --mount-proc
    if "$use_sudo"; then
        set -- sudo -n "$@"
    elif [ "$(id -u)" -ne 0 ]; then
        set -- "$@" --user --map-root-user
    fi
    # /run isolates ip-netns bind mounts. The private PID namespace also removes
    # daemon/echo children if a test or timeout exits before its cleanup runs.
    timeout --signal=TERM --kill-after=10s 10m "$@" sh -eu -c '
        test "$(readlink /proc/self/ns/net)" != "$1"
        export TRAFFIC_MASQ_TEST_HOST_NETNS="$1"
        export RS_WGOBFS_BINARY="$2"
        shift 2
        mount --make-rprivate /
        mount -t tmpfs -o mode=755 tmpfs /run
        mount -t sysfs sysfs /sys
        ip link set lo up
        exec "$@"
    ' namespace-test "$host_netns" "$reference_binary" "$executable" --ignored --test-threads=1 --nocapture
done < "$stage/executables"
