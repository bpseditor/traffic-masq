"""Exercise generated VPN/forwarding rules inside private Linux namespaces."""
import subprocess
import sys


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


for ns, router_if, address in [
    ("client", "lan0", "192.0.2.2/24"),
    ("exit", "tm-wg-0", "198.51.100.2/24"),
]:
    run("ip", "netns", "add", ns)
    run("ip", "link", "add", router_if, "type", "veth", "peer", "name", "peer")
    run("ip", "link", "set", "peer", "netns", ns)
    run("ip", "link", "set", router_if, "up")
    run("ip", "-n", ns, "link", "set", "lo", "up")
    run("ip", "-n", ns, "addr", "add", address, "dev", "peer")
    run("ip", "-n", ns, "link", "set", "peer", "up")
run("ip", "link", "set", "lo", "up")
run("ip", "addr", "add", "192.0.2.1/24", "dev", "lan0")
run("ip", "addr", "add", "198.51.100.1/24", "dev", "tm-wg-0")
run("ip", "-n", "client", "route", "add", "default", "via", "192.0.2.1")
run("ip", "-n", "exit", "route", "add", "192.0.2.0/24", "via", "198.51.100.1")
with open("/proc/sys/net/ipv4/ip_forward", "w") as forwarding:
    forwarding.write("1\n")

server = r'''
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('198.51.100.2', 2222))
print('ready', flush=True)
while True:
    data, address = sock.recvfrom(128)
    sock.sendto(address[0].encode(), address)
'''
probe = r'''
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)
sock.bind((sys.argv[1], 0))
sock.sendto(b'source-probe', ('198.51.100.2', 2222))
seen = sock.recvfrom(128)[0].decode()
assert seen == sys.argv[2], (seen, sys.argv[2])
'''
proc = subprocess.Popen(
    ["ip", "netns", "exec", "exit", "python3", "-u", "-c", server],
    stdout=subprocess.PIPE, text=True,
)
try:
    assert proc.stdout.readline().strip() == "ready"
    run("ip", "netns", "exec", "client", "python3", "-c", probe, "192.0.2.2", sys.argv[1])
    if sys.argv[2] == "host":
        run("python3", "-c", probe, "192.0.2.1", "198.51.100.1")
finally:
    proc.terminate()
    proc.wait()

# A resolver on the router must not turn protected clients' DNS requests into
# unmarked host traffic. Exercise UDP DNS/DoQ and TCP DNS/DoT against listeners
# that really exist, so a closed port cannot masquerade as firewall protection.
import socket

for port in (53, 853):
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        listener = socket.socket(socket.AF_INET, kind)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("192.0.2.1", port))
        listener.settimeout(0.2)
        if kind == socket.SOCK_STREAM:
            listener.listen(1)
        client = r'''
import socket, sys
kind, port = int(sys.argv[1]), int(sys.argv[2])
sock = socket.socket(socket.AF_INET, kind)
sock.settimeout(0.2)
if kind == socket.SOCK_DGRAM:
    sock.sendto(b'dns-leak-probe', ('192.0.2.1', port))
else:
    try:
        sock.connect(('192.0.2.1', port))
    except TimeoutError:
        pass
    else:
        raise AssertionError('local DNS proxy reachable outside VPN')
'''
        try:
            run("ip", "netns", "exec", "client", "python3", "-c", client, str(kind), str(port))
            try:
                if kind == socket.SOCK_DGRAM:
                    listener.recvfrom(128)
                else:
                    listener.accept()
            except TimeoutError:
                pass
            else:
                raise AssertionError(f"DNS leak to local resolver: {kind}, {port}")
        finally:
            listener.close()
