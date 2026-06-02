# Dictionary Reference

The dictionary is what pyrad2 reads to translate `User-Name` into "attribute code 1, type string" and back. This page documents every dictionary feature pyrad2 understands.

For a hands-on tour, run [`examples/dictionary_features.py`](https://github.com/pyradius/pyrad2/blob/master/examples/dictionary_features.py) - backed by [`examples/dictionary.extended`](https://github.com/pyradius/pyrad2/blob/master/examples/dictionary.extended) - which exercises every feature below:

```bash
make dictionary_features
```

## Goal

pyrad2 aims to load real-world FreeRADIUS dictionaries **without modification**. If a dictionary works in FreeRADIUS, it should work here too.

## Data types

Use these in the third column of an `ATTRIBUTE` declaration:

| Type | Description |
| --- | --- |
| `string` | UTF-8 text |
| `octets` | Raw bytes |
| `integer` | 32-bit unsigned integer |
| `signed` | 32-bit signed integer |
| `short` | 16-bit unsigned integer |
| `byte` | 8-bit unsigned integer |
| `integer64` | 64-bit unsigned integer |
| `date` | Seconds since the Unix epoch |
| `ipaddr` | IPv4 address |
| `ipv6addr` | IPv6 address |
| `ipv6prefix` | IPv6 prefix |
| `ipv4prefix` | IPv4 prefix ([RFC 5090](https://datatracker.ietf.org/doc/html/rfc5090)) |
| `combo-ip` | Either IPv4 (4 bytes) or IPv6 (16 bytes); decided by wire length |
| `ifid` | 8-byte Interface-Id ([RFC 3162](https://datatracker.ietf.org/doc/html/rfc3162)) |
| `ether` | MAC address ([RFC 6911](https://datatracker.ietf.org/doc/html/rfc6911)) |
| `abinary` | Ascend filter format |
| `tlv` | TLV container — arbitrarily deep nesting |
| `extended` | RFC 6929 wrapper (types 241–244) |
| `long-extended` | RFC 6929 wrapper (types 245–246) - transparent fragmentation |
| `vsa` | Bare Vendor-Specific attribute ([RFC 2865](https://datatracker.ietf.org/doc/html/rfc2865) code 26) |

FreeRADIUS v4 uses modern type names — `uint8`, `uint16`, `uint32`, `uint64`, `int32` — which pyrad2 accepts as aliases for `byte`, `short`, `integer`, `integer64`, and `signed` respectively. Mix and match freely.

## Attribute options

Add comma-separated options after the type column:

| Option | Effect |
| --- | --- |
| `has_tag` | Attribute carries a one-byte tag prefix ([RFC 2868](https://datatracker.ietf.org/doc/html/rfc2868)) |
| `encrypt=1` | User-Password obfuscation |
| `encrypt=2` | Tunnel-Password / MS-MPPE-Key obfuscation |
| `encrypt=3` | Ascend-Send / Ascend-Receive obfuscation |
| `concat` | Values > 253 bytes split across multiple AVPs on the wire ([RFC 7268 §3.6](https://datatracker.ietf.org/doc/html/rfc7268#section-3.6)) - typical for `EAP-Message`, `CHAP-Challenge` |
| `array` | Multiple fixed-length values packed into one AVP's value field ([RFC 8044 §3.8](https://datatracker.ietf.org/doc/html/rfc8044#section-3.8)) - typical for `DHCP-Router-Address` and other multi-address attributes |
| `virtual` | Server-internal attribute, never emitted on the wire. Used for things like `Auth-Type`, `Client-Shortname` |
| `secret` | Hint that the value is sensitive in logs. Accepted with no wire-format change |

## Vendor-specific format

Per-vendor VSA wire format is honored end-to-end. Declare it on the `VENDOR` line:

```
VENDOR Cisco 9 format=1,1
VENDOR Microsoft 311 format=1,1
VENDOR USR 429 format=4,0
```

The `format=type_len,len_len[,c]` directive controls:

- **`type_len`** - bytes in the vendor-type field: `1`, `2`, or `4`
- **`len_len`** - bytes in the vendor-length field: `0`, `1`, or `2`
- **`c`** (optional) - opts the vendor into [RFC 5904](https://datatracker.ietf.org/doc/html/rfc5904) long-packed VSAs: an extra continuation byte is inserted after the length header, with bit `0x80` flagging fragments. WiMAX (`format=1,1,c`) is the canonical example; Telrad uses the same shape. Pyrad2 handles fragmentation and reassembly transparently — callers see one logical value either way.

If `format=` is omitted, pyrad2 falls back to the RFC 2865 §5.26 default of `1,1`.

## Extended attributes (RFC 6929)

RFC 6929 reserves attribute types 241–246 as **wrappers** that hold sub-attributes. Declare the wrapper, then add sub-attributes using dotted-code notation:

```
ATTRIBUTE Extended-Attribute-1  241    extended
ATTRIBUTE Frag-Status           241.1  integer
ATTRIBUTE Auth-Lifetime         241.2  integer

ATTRIBUTE Extended-Attribute-5  245    long-extended
ATTRIBUTE WiMAX-Blob            245.1  octets
```

| Type | Use |
| --- | --- |
| `extended` (241–244) | Standard extended attribute |
| `long-extended` (245–246) | Extended attribute with fragmentation for values > 251 bytes |

### Access on the packet

Sub-attributes are accessed by name; the parent returns a dict of sub-attribute values:

```python
packet["Frag-Status"] = 5
packet["Auth-Lifetime"] = 3600

packet["Extended-Attribute-1"]
# -> {"Frag-Status": [5], "Auth-Lifetime": [3600]}
```

`long-extended` values larger than 251 bytes are fragmented on send and reassembled on receive. Callers see one logical value either way.

## Extended-Vendor-Specific (EVS)

EVS ([RFC 6929 §2.3](https://datatracker.ietf.org/doc/html/rfc6929#section-2.3)) is how a vendor carries its own attributes inside an extended wrapper. The `evs` type marks the slot, and `BEGIN-VENDOR <name> parent=<evs-attr>` scopes the vendor's attributes underneath it:

```
ATTRIBUTE Extended-Attribute-1        241     extended
ATTRIBUTE Extended-Vendor-Specific-1  241.26  evs

VENDOR Example 12345

BEGIN-VENDOR Example parent=Extended-Vendor-Specific-1
ATTRIBUTE Example-Attr-1  1  string
ATTRIBUTE Example-Attr-2  2  integer
END-VENDOR Example
```

Access EVS attributes by name like any other attribute:

```python
packet["Example-Attr-1"] = "hello"
```

The wire encoding wraps the vendor id and vendor type into the extended payload. `long-extended` EVS values fragment and reassemble the same way as plain `long-extended` attributes.

## Nested TLVs

TLV containers can hold further TLV containers to arbitrary depth. Sub-attributes use dotted-code notation at every level:

```
ATTRIBUTE Extended-Attribute-1   241      extended
ATTRIBUTE IP-Port-Limit-Info     241.5    tlv
ATTRIBUTE IP-Port-Type           241.5.1  integer
ATTRIBUTE IP-Port-Limit          241.5.2  integer
```

The packet API recurses through the nesting so each level surfaces as a `{sub_name: [values]}` map:

```python
packet["IP-Port-Type"] = 7
packet["IP-Port-Limit"] = 100

packet["Extended-Attribute-1"]
# -> {"IP-Port-Limit-Info": {"IP-Port-Type": [7], "IP-Port-Limit": [100]}}
```

Wire encoding nests `<type><length><value>` triplets at every level inside the outer envelope. This covers the RFC 6929 / 7499 / 8045 dictionaries among others.

## Real-world compatibility

pyrad2 is regression-tested against the upstream FreeRADIUS dictionary corpus and packet test vectors. See the [FreeRADIUS Conformance](conformance.md) page for the suite, its results, and the small number of known corner cases.

If you hit something that FreeRADIUS handles but pyrad2 doesn't, please [open an issue](https://github.com/pyradius/pyrad2/issues).
