"""Run only under unshare -n; verify route fallthrough cannot leak transport."""
import json
import os
import socket
import subprocess
import sys

assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
mark, table, priority = map(int, sys.argv[1:])
guard = sys.stdin.read()


def run(*args, input=None):
    return subprocess.check_output(args, input=input, text=True)


run("ip", "link", "set", "lo", "up")
for name, address in [("uplink", "192.0.2.1/24"), ("previous", "10.0.0.1/24")]:
    run("ip", "link", "add", name, "type", "dummy")
    run("ip", "address", "add", address, "dev", name)
    run("ip", "link", "set", name, "up")
run("ip", "route", "add", "default", "dev", "uplink")
run("ip", "route", "add", "table", str(table), "default", "dev", "previous")
run("ip", "rule", "add", "priority", str(priority), "fwmark", str(mark),
    "lookup", str(table))
audit = """table inet audit {
 chain output {
  type filter hook output priority 20; policy accept;
  oifname "uplink" counter
  oifname "previous" counter
 }
}
"""
run("nft", "-f", "-", input=guard + audit)


def counters():
    data = json.loads(run("nft", "-j", "list", "table", "inet", "audit"))
    return [expr["counter"]["packets"]
            for entry in data["nftables"] if "rule" in entry
            for expr in entry["rule"]["expr"] if "counter" in expr]


def send(value):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, value)
        try:
            sock.sendto(b"transport-probe", ("198.51.100.2", 51820))
        except OSError:
            pass  # nft drop may return EPERM to the sender.


send(mark)
assert counters() == [0, 1], counters()
# Link deletion removes the per-hop default; lookup now falls through to main.
run("ip", "link", "del", "previous")
route = json.loads(run("ip", "-j", "route", "get", "198.51.100.2",
                      "mark", str(mark)))
assert route[0]["dev"] == "uplink", route
send(mark)
assert counters() == [0, 1], counters()
# The guard must not break unrelated underlay traffic.
send(0)
assert counters() == [1, 1], counters()

print(run("nft", "-j", "list", "table", "inet", "traffic_masq_transport_1"))
