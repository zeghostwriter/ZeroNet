#!/usr/bin/env python3
"""Cut Xray geosite/geoip .dat files down to the tags ZeroNet's rules use.

The Android app ships these trimmed files so Iran-direct routing, ad blocking
and private-range rules work from the first launch, offline, without a 23 MB
geoip.dat download over a filtered, metered network.

Both formats are a protobuf list whose field 1 repeats length-delimited
entries, each starting with its tag (field 1, a string). Kept entries are
copied byte for byte, so nothing inside them is re-encoded.

Usage:
  trim-geodata.py dlc.dat   out/geosite.dat category-ir category-ads-all
  trim-geodata.py geoip.dat out/geoip.dat   ir private
"""
import sys


def varint(buf, at):
    shift = value = 0
    while True:
        byte = buf[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, at
        shift += 7


def encode_varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def entries(buf):
    at = 0
    while at < len(buf):
        key, at = varint(buf, at)
        if key != (1 << 3 | 2):
            raise ValueError(f"unexpected top-level field key {key} at {at}")
        length, at = varint(buf, at)
        yield buf[at:at + length]
        at += length


def tag_of(entry):
    key, at = varint(entry, 0)
    if key != (1 << 3 | 2):
        raise ValueError("entry does not start with its tag")
    length, at = varint(entry, at)
    return entry[at:at + length].decode().lower()


def main():
    source, target, *keep = sys.argv[1:]
    keep = {tag.lower() for tag in keep}
    data = open(source, "rb").read()
    out = bytearray()
    found = set()
    for entry in entries(data):
        tag = tag_of(entry)
        if tag in keep:
            found.add(tag)
            out += encode_varint(1 << 3 | 2) + encode_varint(len(entry)) + entry
    missing = keep - found
    if missing:
        sys.exit(f"{source}: tags not found: {', '.join(sorted(missing))}")
    open(target, "wb").write(out)
    print(f"{target}: {len(out)} bytes, tags {', '.join(sorted(found))}")


if __name__ == "__main__":
    main()
