#!/usr/bin/env python3
"""Linux-native Huawei MUT (Multicast Upgrade Tool) sender.

Reflashing the HG531 V1 over the LAN during bootloader window.
Protocol reverse-engineered from HuaweiMUT.exe (see huawei-mut-repo/_research/PROTOKOL.md).

Multicast UDP 224.0.0.119:13456, 1086-byte packets (62B header + 1024B chunk).
"""
import argparse
import os
import socket
import struct
import sys
import threading
import time
import zlib

MCAST_IP = "224.0.0.119"
PORT = 13456
CHUNK = 1024
HDR = 62
PKT = 1086

OP_DATA, OP_LAST, OP_INIT = 1, 2, 4


def crc32(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF


def parse_ini(path):
    kv = {}
    for line in open(path):
        s = line.strip()
        if "=" in s and not s.startswith("#"):
            k, v = s.split("=", 1)
            kv[k] = v
    return kv


def parse_partitions(s):
    out = []
    for e in s.split("|"):
        name, rng, flag = e.split(",")
        start, end = rng.split("-")
        out.append((name, int(start, 16), int(end, 16), flag.strip().lower() == "cover"))
    return out


def build_packet(opcode, data, seq, total, fwcrc, pkg, prod, pcb=0):
    pad = data + b"\x00" * (CHUNK - len(data))
    ccrc = crc32(pad)
    cw = (opcode << 29) | 0x00000400
    h = struct.pack("<I", cw)
    h += struct.pack("<I", seq)
    h += struct.pack("<I", ccrc)
    h += struct.pack("<I", total)
    h += struct.pack("<I", fwcrc)
    h += pkg.encode("ascii", "replace")[:20].ljust(20, b"\x00")
    h += struct.pack("<H", pcb & 0xFFFF)
    h += prod.encode("ascii", "replace")[:20].ljust(20, b"\x00")
    assert len(h) == HDR, len(h)
    p = h + pad
    assert len(p) == PKT, len(p)
    return p


def build_init(parts):
    p = b""
    for name, start, end, cover in parts:
        p += name.encode("ascii", "replace")[:20].ljust(20, b"\x00")
        p += struct.pack("<II", start, end)
        p += b"\x02" if cover else b"\x01"
        p += b"\x00\x00\x00"
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--ini", required=True)
    ap.add_argument("--iface-ip", required=True, help="source IP of the NIC (e.g. 192.168.1.104)")
    ap.add_argument("--interval-ms", type=float, default=5.0)
    ap.add_argument("--ttl", type=int, default=4, help="multicast TTL")
    ap.add_argument("--passes", type=int, default=0, help="0=forever")
    ap.add_argument("--dest", choices=["multicast", "broadcast", "both"], default="multicast",
                    help="packet destination (broadcast bypasses IGMP snooping)")
    ap.add_argument("--listen", action="store_true", help="print any replies from the router")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    fw = open(args.bin, "rb").read()
    ini = parse_ini(args.ini)
    parts = parse_partitions(ini["PARTITIONS"])
    pkg, prod = ini["PACKAGE_ID"], ini["PRODUCT_ID"]
    fwcrc = crc32(fw)
    total = len(fw)
    nchunks = (total + CHUNK - 1) // CHUNK

    print("[cfg] image      : %s (%d bytes)" % (os.path.basename(args.bin), total))
    print("[cfg] pkg/prod   : %s / %s" % (pkg, prod))
    print("[cfg] partitions : %s" % "; ".join("%s[0x%X-0x%X,%s]" % (n, s, e, "cover" if c else "uncov") for n, s, e, c in parts))
    print("[cfg] fw CRC32   : %d (0x%08X)  ini=%s" % (fwcrc, fwcrc, ini.get("FIRMWARE_CRC_SUM")))
    print("[cfg] chunks     : %d, interval %.1f ms, pass ~%.1fs" % (nchunks, args.interval_ms, nchunks * args.interval_ms / 1000.0))
    dests = []
    if args.dest in ("multicast", "both"):
        dests.append((MCAST_IP, PORT))
    if args.dest in ("broadcast", "both"):
        dests.append(("255.255.255.255", PORT))
    print("[cfg] source ip  : %s   dest: %s" % (args.iface_ip, ", ".join("%s:%d" % d for d in dests)))

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.bind((args.iface_ip, PORT))
    except OSError as e:
        print("[warn] bind(%s:%d) failed: %s -> 0.0.0.0" % (args.iface_ip, PORT, e))
        s.bind(("0.0.0.0", PORT))

    if args.dest in ("multicast", "both"):
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                         socket.inet_aton(MCAST_IP) + socket.inet_aton(args.iface_ip))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, args.ttl)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.iface_ip))
        except OSError as e:
            print("[warn] multicast setup: %s" % e)

    s.settimeout(0.0)
    running = {"v": True}

    if args.listen:
        def rx():
            while running["v"]:
                try:
                    d, a = s.recvfrom(4096)
                    print("\n[<<] REPLY %s %d bytes: %s" % (a, len(d), d[:48].hex()))
                except (socket.timeout, BlockingIOError):
                    time.sleep(0.01)
                except OSError:
                    break
        threading.Thread(target=rx, daemon=True).start()

    init_pkt = build_packet(OP_INIT, build_init(parts), 0, total, fwcrc, pkg, prod)

    # pre-build all data packets once (memory ~3.7MB)
    data_pkts = []
    off, seq = 0, 1
    while off < total:
        rem = total - off
        if rem <= CHUNK:
            data_pkts.append(build_packet(OP_LAST, fw[off:off + rem], seq, total, fwcrc, pkg, prod))
            break
        data_pkts.append(build_packet(OP_DATA, fw[off:off + CHUNK], seq, total, fwcrc, pkg, prod))
        off += CHUNK
        seq += 1
    print("[cfg] built %d data packets (+1 init)" % len(data_pkts))

    iv = args.interval_ms / 1000.0
    try:
        p = 0
        while running["v"]:
            p += 1
            t0 = time.time()
            for d in dests:
                s.sendto(init_pkt, d)
            time.sleep(iv)
            for i, pkt in enumerate(data_pkts):
                for d in dests:
                    s.sendto(pkt, d)
                if iv:
                    time.sleep(iv)
                if args.verbose and i % 500 == 0:
                    print("  pass %d chunk %d/%d" % (p, i, len(data_pkts)))
            dt = time.time() - t0
            print("[pass %d] sent %d packets in %.1fs (%.0f pkt/s)" % (p, len(data_pkts) + 1, dt, (len(data_pkts) + 1) / dt))
            if args.passes and p >= args.passes:
                print("[done] reached %d passes" % p)
                break
            time.sleep(iv * 2)
    except KeyboardInterrupt:
        print("\n[stop] interrupted")
    finally:
        running["v"] = False
        s.close()


if __name__ == "__main__":
    main()
