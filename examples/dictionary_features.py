#!/usr/bin/python
"""Round-trip demos of the dictionary features pyrad2 added recently.

Run with::

    PYTHONPATH=. uv run examples/dictionary_features.py

or via the Makefile::

    make dictionary_features

Each section sets attributes on a packet, encodes the attribute block to
wire bytes, decodes it back, and prints what came out — so you can see
both the on-the-wire shape and the round-tripped Python value.

The dictionary lives in ``examples/dictionary.extended`` and exercises:

* ``ifid`` (RFC 3162) and ``ether`` (RFC 6911) data types
* The ``concat`` attribute option (RFC 7268 §3.6)
* Per-vendor ``format=`` directive
* RFC 6929 ``extended`` and ``long-extended`` containers, with
  transparent fragmentation
* RFC 6929 §2.3 Extended-Vendor-Specific via ``BEGIN-VENDOR parent=``
"""

import os
import struct

from loguru import logger

from pyrad2 import packet
from pyrad2.dictionary import Dictionary

HERE = os.path.dirname(os.path.abspath(__file__))
DICTIONARY_PATH = os.path.join(HERE, "dictionary.extended")


def fresh_packet(dictionary: Dictionary) -> packet.Packet:
    """A bare packet wired to the example dictionary, ready for attributes."""
    return packet.Packet(
        id=1,
        secret=b"secret",
        authenticator=b"0123456789ABCDEF",
        dict=dictionary,
    )


def encode_and_decode(pkt: packet.Packet, dictionary: Dictionary) -> packet.Packet:
    """Encode ``pkt``'s attributes, then decode them into a fresh packet."""
    attrs = pkt._pkt_encode_attributes()
    header = struct.pack("!BBH", 1, 1, 20 + len(attrs)) + b"0123456789ABCDEF"
    decoded = fresh_packet(dictionary)
    decoded.decode_packet(header + attrs)
    return decoded


def demo_ifid_and_ether(dictionary: Dictionary) -> None:
    logger.info("=== ifid and ether ===")
    pkt = fresh_packet(dictionary)
    pkt["Framed-Interface-Id"] = "0011:2233:4455:6677"
    pkt["Test-Mac-Address"] = "aa:bb:cc:dd:ee:ff"

    decoded = encode_and_decode(pkt, dictionary)

    logger.info("Framed-Interface-Id wire: {}", pkt[96][0].hex())
    logger.info("Test-Mac-Address    wire: {}", pkt[190][0].hex())
    logger.info("Round-trip Framed-Interface-Id: {}", decoded["Framed-Interface-Id"])
    logger.info("Round-trip Test-Mac-Address:    {}", decoded["Test-Mac-Address"])


def demo_concat(dictionary: Dictionary) -> None:
    logger.info("=== concat (RFC 7268 §3.6) ===")
    pkt = fresh_packet(dictionary)
    payload = b"A" * 300  # one AVP can't hold this — must split
    pkt[200] = [payload]

    wire = pkt._pkt_encode_attributes()
    # The encoder produces multiple AVPs of attribute type 200.
    offset = 0
    avp_count = 0
    while offset < len(wire):
        avp_count += 1
        offset += wire[offset + 1]
    logger.info("Original value is {} bytes", len(payload))
    logger.info("Wire output is {} bytes split across {} AVPs", len(wire), avp_count)

    decoded = encode_and_decode(pkt, dictionary)
    logger.info(
        "After decode, the receiver sees one entry of {} bytes",
        len(decoded[200][0]),
    )
    logger.info("Bytes preserved: {}", decoded[200][0] == payload)


def demo_vendor_format(dictionary: Dictionary) -> None:
    logger.info("=== Vendor format=4,0 (USR-style, no inner length field) ===")
    pkt = fresh_packet(dictionary)
    pkt[(429, 5)] = [b"hello"]

    wire = pkt._pkt_encode_attributes()
    # [26][len][vendor=4 bytes 0x000001AD][vsa_type=4 bytes 0x00000005][value]
    # The VSA inner header has no length field because format=4,0.
    logger.info("Encoded {} bytes: {}", len(wire), wire.hex())

    decoded = encode_and_decode(pkt, dictionary)
    logger.info("Decoded (429, 5): {}", decoded[(429, 5)])


def demo_extended(dictionary: Dictionary) -> None:
    logger.info("=== RFC 6929 extended (241-244) ===")
    pkt = fresh_packet(dictionary)
    pkt.add_attribute("Frag-Status", "Fragmented")  # named VALUE
    pkt.add_attribute("Auth-Lifetime", 3600)

    wire = pkt._pkt_encode_attributes()
    logger.info("Two extended AVPs encoded to {} bytes: {}", len(wire), wire.hex())

    decoded = encode_and_decode(pkt, dictionary)
    # Read back through the parent wrapper to get a dict of sub-attr name → values.
    logger.info("Decoded Extended-Attribute-1: {}", decoded["Extended-Attribute-1"])


def demo_long_extended(dictionary: Dictionary) -> None:
    logger.info("=== RFC 6929 long-extended (245-246) with fragmentation ===")
    pkt = fresh_packet(dictionary)
    blob = bytes(range(256)) * 3  # 768 bytes, larger than 251 — must fragment
    pkt[245] = {1: [blob]}

    wire = pkt._pkt_encode_attributes()
    # Each fragment starts with [245][len][1][flags]. Count the More bits set.
    offset = 0
    fragments = 0
    while offset < len(wire):
        avp_len = wire[offset + 1]
        fragments += 1
        offset += avp_len
    logger.info(
        "{}-byte value fragmented into {} AVPs ({} wire bytes total)",
        len(blob),
        fragments,
        len(wire),
    )

    decoded = encode_and_decode(pkt, dictionary)
    logger.info("Reassembled value: {} bytes", len(decoded[245][1][0]))
    logger.info("Bytes match original: {}", decoded[245][1][0] == blob)


def demo_evs(dictionary: Dictionary) -> None:
    logger.info("=== RFC 6929 §2.3 EVS (Extended-Vendor-Specific) ===")
    pkt = fresh_packet(dictionary)
    pkt.add_attribute("Example-User-Tier", "platinum")
    pkt.add_attribute("Example-Bandwidth-Mbps", 1000)

    wire = pkt._pkt_encode_attributes()
    logger.info("Two EVS AVPs encoded to {} bytes: {}", len(wire), wire.hex())

    decoded = encode_and_decode(pkt, dictionary)
    logger.info("Example-User-Tier: {}", decoded["Example-User-Tier"])
    logger.info("Example-Bandwidth-Mbps: {}", decoded["Example-Bandwidth-Mbps"])


def main() -> None:
    dictionary = Dictionary(DICTIONARY_PATH)
    logger.info("Loaded {} attributes from {}", len(dictionary), DICTIONARY_PATH)

    demo_ifid_and_ether(dictionary)
    demo_concat(dictionary)
    demo_vendor_format(dictionary)
    demo_extended(dictionary)
    demo_long_extended(dictionary)
    demo_evs(dictionary)


if __name__ == "__main__":
    main()
