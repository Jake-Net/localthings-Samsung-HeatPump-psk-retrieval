"""Test whether the Android emulator's slirp NAT forwards outbound multicast.

Listens on a host UDP port (joined to 224.0.1.187) and asks the emulator to
send one unicast and one multicast datagram to it.
"""
import socket
import struct
import subprocess
import threading
import time

ADB = r"C:\Users\kelly\.android\studio\SDK\platform-tools\adb.exe"
IFACE = "192.168.6.235"
GROUP = "224.0.1.187"
PORT = 15683
DURATION = 14

received = []


def listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", PORT))
    mreq = struct.pack("4s4s", socket.inet_aton(GROUP),
                       socket.inet_aton(IFACE))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(1.0)
    deadline = time.monotonic() + DURATION
    while time.monotonic() < deadline:
        try:
            data, src = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        received.append((src, data))
        print("GOT %r from %s" % (data, src), flush=True)
    sock.close()


def send(target, label):
    cmd = [ADB, "shell", "echo %s | nc -u -w 1 %s %d" % (label, target, PORT)]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=10)
        print("send %s -> rc=%d %s" % (target, out.returncode,
                                       out.stderr.decode(errors="replace")[:100]),
              flush=True)
    except Exception as exc:
        print("send %s failed: %s" % (target, exc), flush=True)


if __name__ == "__main__":
    thread = threading.Thread(target=listener, daemon=True)
    thread.start()
    time.sleep(1.5)
    send(IFACE, "unicast")
    time.sleep(2.0)
    send(GROUP, "multicast")
    time.sleep(1.0)
    send("192.168.6.243", "toappliance")
    thread.join(timeout=DURATION + 2)
    print("total datagrams received: %d" % len(received))
