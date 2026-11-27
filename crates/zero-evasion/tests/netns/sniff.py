#!/usr/bin/env python3
"""Record the TCP segments to port 443 that pass an interface of this namespace.

One JSON line per segment: the interface, the TTL it carried, whether it has the
TCP MD5 option (kind 19), and which of the two names its payload contains. The
testbed reads these to see what a filter sitting on that router would see.

Why a packet *ring* and not a plain raw socket: the no-root decoy sends a page
of its own with `vmsplice` and overwrites it with the real hello once the decoy
has left. Across a virtual link the packet still points at that page, so a
socket that copies the bytes when the reader gets round to them reads the real
hello. A TPACKET ring copies the frame inside the kernel at the instant it is
tapped, which is what a hardware NIC's DMA would have carried away.

Usage: sniff.py LOGFILE REAL_NAME[,REAL_NAME...] DECOY_MARKER[,DECOY_MARKER...]
"""
import json
import mmap
import select
import socket
import struct
import sys

SOL_PACKET, PACKET_VERSION, PACKET_RX_RING, TPACKET_V2 = 263, 10, 5, 1
BLOCK, BLOCKS, FRAME = 1 << 16, 16, 2048
FRAMES = BLOCK // FRAME * BLOCKS

log = sys.argv[1]
decoys = [name.encode() for name in sys.argv[3].split(",")]
reals = [name.encode() for name in sys.argv[2].split(",")]
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V2)
s.setsockopt(SOL_PACKET, PACKET_RX_RING, struct.pack("IIII", BLOCK, BLOCKS, FRAME, FRAMES))
ring = mmap.mmap(s.fileno(), BLOCK * BLOCKS)
out = open(log, "a", buffering=1)
poller = select.poll()
poller.register(s, select.POLLIN)


def segment(frame, iface):
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    if ip[9] != 6:
        return
    tcp = ip[ihl:]
    if struct.unpack("!H", tcp[2:4])[0] not in (443, 444):
        return
    off = (tcp[12] >> 4) * 4
    options, md5, i = tcp[20:off], False, 0
    while i < len(options):
        kind = options[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(options) or options[i + 1] < 2:
            break
        md5 |= kind == 19
        i += options[i + 1]
    payload = tcp[off:]
    if payload:
        out.write(json.dumps({
            "iface": iface, "ttl": ip[8], "md5": md5, "len": len(payload),
            "seq": struct.unpack("!I", tcp[4:8])[0], "sport": struct.unpack("!H", tcp[0:2])[0],
            "has_real": any(name in payload for name in reals), "has_decoy": any(name in payload for name in decoys),
        }) + "\n")


index = 0
while True:
    offset = index * FRAME
    status = struct.unpack_from("I", ring, offset)[0]
    if not status & 1:  # TP_STATUS_USER
        poller.poll(1000)
        continue
    snaplen, mac = struct.unpack_from("IH", ring, offset + 8)[0], struct.unpack_from("H", ring, offset + 12)[0]
    ifindex = struct.unpack_from("i", ring, offset + 36)[0]
    try:
        iface = socket.if_indextoname(ifindex)
    except OSError:
        iface = str(ifindex)
    segment(bytes(ring[offset + mac: offset + mac + snaplen]), iface)
    struct.pack_into("I", ring, offset, 0)  # hand the frame back to the kernel
    index = (index + 1) % FRAMES
