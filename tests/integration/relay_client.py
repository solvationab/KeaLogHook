#!/usr/bin/env python3
"""Minimal DHCPv4 relay agent simulator.

Runs a full DORA exchange followed by a renewal and a release, sending vendor/user class
options and relay agent information (option 82). Prints the assigned lease as JSON.
"""

import argparse
import json
import os
import socket
import struct
import sys

MAGIC_COOKIE = b"\x63\x82\x53\x63"
DISCOVER, OFFER, REQUEST, ACK, RELEASE = 1, 2, 3, 5, 7


def option(code, data):
    return bytes([code, len(data)]) + data


def build_packet(msg_type, xid, mac, giaddr, ciaddr="0.0.0.0", options=()):
    chaddr = mac + bytes(16 - len(mac))
    header = struct.pack(
        "!BBBBIHH4s4s4s4s",
        1, 1, len(mac), 1, xid, 0, 0,
        socket.inet_aton(ciaddr), bytes(4), bytes(4), socket.inet_aton(giaddr),
    )
    body = header + chaddr + bytes(192) + MAGIC_COOKIE
    body += option(53, bytes([msg_type]))
    body += option(61, b"\x01" + mac)
    for opt in options:
        body += opt
    return body + b"\xff"


def parse_reply(data, xid):
    if len(data) < 240 or struct.unpack("!I", data[4:8])[0] != xid:
        return None
    if data[236:240] != MAGIC_COOKIE:
        return None
    opts = {}
    pos = 240
    while pos < len(data) and data[pos] != 0xFF:
        if data[pos] == 0:
            pos += 1
            continue
        code, length = data[pos], data[pos + 1]
        opts[code] = data[pos + 2:pos + 2 + length]
        pos += 2 + length
    return socket.inet_ntoa(data[16:20]), opts


class Relay:
    def __init__(self, relay_ip, server_ip, mac):
        self.relay_ip = relay_ip
        self.server = (server_ip, 67)
        self.mac = mac
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((relay_ip, 67))
        self.sock.settimeout(5)
        self.xid = int.from_bytes(os.urandom(4), "big")
        self.agent_info = option(
            82,
            option(1, b"port-7")
            + option(2, bytes.fromhex("0a1b2c3d4e5f"))
            + option(9, bytes.fromhex("00000123aabb"))
            + option(10, b"\x01"),
        )

    def send(self, msg_type, ciaddr="0.0.0.0", options=()):
        packet = build_packet(
            msg_type,
            self.xid,
            self.mac,
            self.relay_ip,
            ciaddr,
            list(options)
            + [option(60, b"test-vendor"), option(77, b"\x05class"), self.agent_info],
        )
        self.sock.sendto(packet, self.server)

    def expect(self, wanted):
        while True:
            try:
                data, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                sys.exit("timed out waiting for message type %d" % wanted)
            reply = parse_reply(data, self.xid)
            if reply and reply[1].get(53) == bytes([wanted]):
                return reply


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--relay", required=True)
    parser.add_argument("--mac", default="aa:bb:cc:00:00:01")
    args = parser.parse_args()

    relay = Relay(args.relay, args.server, bytes.fromhex(args.mac.replace(":", "")))

    relay.send(DISCOVER)
    offered, opts = relay.expect(OFFER)
    server_id = opts[54]

    relay.send(REQUEST, options=[option(50, socket.inet_aton(offered)), option(54, server_id)])
    leased, _ = relay.expect(ACK)
    if leased != offered:
        sys.exit("ACK address %s differs from offer %s" % (leased, offered))

    relay.send(REQUEST, ciaddr=leased)
    renewed, _ = relay.expect(ACK)
    if renewed != leased:
        sys.exit("renewal ACK address %s differs from lease %s" % (renewed, leased))

    relay.send(RELEASE, ciaddr=leased, options=[option(54, server_id)])

    print(json.dumps({"ip": leased, "mac": args.mac}))


if __name__ == "__main__":
    main()
