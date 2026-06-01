"""
RADIUS uses dictionaries to define the attributes that can
be used in packets. The Dictionary class stores the attribute
definitions from one or more dictionary files.

Dictionary files are textfiles with one command per line.
Comments are specified by starting with a # character, and empty
lines are ignored.

The commands supported are::

```
ATTRIBUTE <attribute> <code> <type> [<vendor>]
specify an attribute and its type

VALUE <attribute> <valuename> <value>
specify a value attribute

VENDOR <name> <id>
specify a vendor ID

BEGIN-VENDOR <vendorname>
begin definition of vendor attributes

END-VENDOR <vendorname>
end definition of vendor attributes
```


The datatypes currently supported are:

```
+---------------+----------------------------------------------+
| type          | description                                  |
+===============+==============================================+
| string        | ASCII string                                 |
+---------------+----------------------------------------------+
| ipaddr        | IPv4 address                                 |
+---------------+----------------------------------------------+
| date          | 32 bits UNIX                                 |
+---------------+----------------------------------------------+
| octets        | arbitrary binary data                        |
+---------------+----------------------------------------------+
| abinary       | ascend binary data                           |
+---------------+----------------------------------------------+
| ipv6addr      | 16 octets in network byte order              |
+---------------+----------------------------------------------+
| ipv6prefix    | 18 octets in network byte order              |
+---------------+----------------------------------------------+
| integer       | 32 bits unsigned number                      |
+---------------+----------------------------------------------+
| signed        | 32 bits signed number                        |
+---------------+----------------------------------------------+
| short         | 16 bits unsigned number                      |
+---------------+----------------------------------------------+
| byte          | 8 bits unsigned number                       |
+---------------+----------------------------------------------+
| tlv           | Nested tag-length-value                      |
+---------------+----------------------------------------------+
| integer64     | 64 bits unsigned number                      |
+---------------+----------------------------------------------+
```

Attribute options recognized after the type column:

```
has_tag    attribute carries a one-byte tag prefix (RFC 2868)
encrypt=N  apply encryption flavour N (1, 2, or 3)
concat     attribute may be split across multiple AVPs whose
           values the receiver must concatenate (RFC 7268 §3.6).
           Typical examples: EAP-Message, CHAP-Challenge.
```

Vendor format specifications honor the ``format=type_len,len_len`` syntax
where ``type_len`` is 1, 2, or 4 and ``len_len`` is 0, 1, or 2. The
default (RFC 2865 §5.26) is ``format=1,1``. Stored formats are applied
when encoding and decoding Vendor-Specific Attributes for that vendor.

RFC 6929 extended attributes are recognized via the dotted-code syntax
(e.g. ``ATTRIBUTE Frag-Status 241.1 integer``) when the parent (type
codes 241-246) is declared as ``extended`` or ``long-extended``. The
fragmentation flag for ``long-extended`` is handled transparently on
both encode and decode.

Extended-Vendor-Specific (EVS, RFC 6929 §2.3) is supported through the
``evs`` datatype combined with FreeRADIUS's ``BEGIN-VENDOR <name>
parent=<evs-attr>`` syntax. Every ATTRIBUTE inside such a block becomes
an EVS-VSA carried under the named extended wrapper.

Limitations:
    * Nested TLVs deeper than two levels are not yet supported.
"""

from copy import copy
from typing import Any, Dict, Hashable, Optional

from pyrad2 import bidict, dictfile, tools
from pyrad2.constants import DATATYPES
from pyrad2.exceptions import ParseError

RadiusAttributeValue = int | str | bytes


class Attribute:
    """Represents a RADIUS attribute.

    Attributes:
        name (str): Attribute name
        code (int): RADIUS code
        type (str): Data type (e.g., 'string', 'ipaddr')
        vendor (int): Vendor ID (0 if standard)
        has_tag (bool): Whether attribute supports tags
        encrypt (int): Encryption type (0 = none)
        concat (bool): Whether values longer than 253 bytes are split
            across multiple AVPs on the wire and concatenated on decode.
        values (bidict.BiDict): Mapping of named values to their codes
    """

    def __init__(
        self,
        name: str,
        code: int,
        datatype: str,
        is_sub_attribute: bool = False,
        vendor: str = "",
        values=None,
        encrypt: int = 0,
        has_tag: bool = False,
        concat: bool = False,
    ):
        if datatype not in DATATYPES:
            raise ValueError("Invalid data type")
        self.name = name
        self.code = code
        self.type = datatype
        self.vendor = vendor
        self.encrypt = encrypt
        self.has_tag = has_tag
        self.concat = concat
        self.values = bidict.BiDict()
        self.sub_attributes: dict = {}
        self.parent = None
        self.is_sub_attribute = is_sub_attribute
        if values:
            for key, value in values.items():
                self.values.add(key, value)


VENDOR_FORMAT_DEFAULT: tuple[int, int] = (1, 1)


class Dictionary:
    """RADIUS dictionary class.

    This class stores all information about vendors, attributes and their
    values as defined in RADIUS dictionary files.

    Attributes:
        vendors (bidict.BiDict): bidict mapping vendor name to vendor code
        attrindex (bidict.BiDict): bidict mapping
        attributes (bidict.BiDict): bidict mapping attribute name to attribute class
        vendor_formats (dict[int, tuple[int, int]]): mapping vendor code to
            its ``(type_len, len_len)`` VSA wire format. Vendors without an
            explicit ``format=`` declaration default to ``(1, 1)``.
    """

    def __init__(
        self,
        dict: Optional[str] = None,
        *dicts,
        include_base_dir: Optional[str] = None,
    ):
        """Initialize a new Dictionary instance and load specified dictionary files.

        Args:
            dict (str): Path of dictionary file or file-like object to read
            dicts (list): Sequence of strings or files
            include_base_dir (str): Trusted base directory for
                ``$INCLUDE`` resolution. Nested includes whose resolved
                path escapes this directory raise ``ParseError``.
                Defaults to the directory of each entry-point file.
                Set this explicitly when loading dictionaries from
                untrusted sources.
        """
        self.vendors = bidict.BiDict()
        self.vendors.add("", 0)
        self.attrindex = bidict.BiDict()
        self.attributes: Dict[Hashable, Any] = {}
        self.vendor_formats: Dict[int, tuple[int, int]] = {}
        self.defer_parse: list[tuple[Dict, list]] = []
        self._include_base_dir = include_base_dir

        if dict:
            self.read_dictionary(dict)

        for i in dicts:
            self.read_dictionary(i)

    def vendor_format(self, vendor_id: int) -> tuple[int, int]:
        """Return the ``(type_len, len_len)`` VSA wire format for ``vendor_id``.

        Vendors without an explicit ``format=`` declaration use the RFC 2865
        §5.26 default of one-byte type and one-byte length.
        """
        return self.vendor_formats.get(vendor_id, VENDOR_FORMAT_DEFAULT)

    def __len__(self) -> int:
        """Return the number of attributes defined."""
        return len(self.attributes)

    def __getitem__(self, key: Hashable):
        """Retrieve an Attribute by name."""
        return self.attributes[key]

    def __contains__(self, key: Hashable) -> bool:
        """Check if an attribute is defined in the dictionary."""
        return key in self.attributes

    has_key = __contains__

    def __parse_attribute(self, state: dict, tokens: list):
        """Parse an ATTRIBUTE line from a dictionary file."""
        if len(tokens) not in [4, 5]:
            raise ParseError(
                "Incorrect number of tokens for attribute definition",
                file=state["file"],
                line=state["line"],
            )

        vendor = state["vendor"]
        has_tag = False
        encrypt = 0
        concat = False
        if len(tokens) >= 5:

            def keyval(o):
                kv = o.split("=")
                if len(kv) == 2:
                    return (kv[0], kv[1])
                else:
                    return (kv[0], None)

            options = [keyval(o) for o in tokens[4].split(",")]
            options_recognized = False
            for key, val in options:
                if key == "has_tag":
                    has_tag = True
                    options_recognized = True
                elif key == "encrypt":
                    if val not in ["1", "2", "3"]:
                        raise ParseError(
                            "Illegal attribute encryption: %s" % val,
                            file=state["file"],
                            line=state["line"],
                        )
                    encrypt = int(val)
                    options_recognized = True
                elif key == "concat":
                    concat = True
                    options_recognized = True

            # When the trailing column isn't a recognized option list, fall
            # back to treating it as a vendor name (e.g. ``ATTRIBUTE Foo 1
            # integer Cisco``).
            if not options_recognized:
                vendor = tokens[4]
                if not self.vendors.has_forward(vendor):
                    raise ParseError(
                        "Unknown vendor " + vendor,
                        file=state["file"],
                        line=state["line"],
                    )

        (attribute, code, datatype) = tokens[1:4]

        codes = code.split(".")

        # Codes can be sent as hex, or octal or decimal string representations.
        tmp = []
        for c in codes:
            if c.startswith("0x"):
                tmp.append(int(c, 16))
            elif c.startswith("0o"):
                tmp.append(int(c, 8))
            else:
                tmp.append(int(c, 10))
        codes = tmp

        is_sub_attribute = len(codes) > 1
        if len(codes) == 2:
            code = int(codes[1])
            parent_code = int(codes[0])
        elif len(codes) == 1:
            code = int(codes[0])
            parent_code = None
        else:
            raise ParseError("nested tlvs are not supported")

        datatype = datatype.split("[")[0]

        if datatype not in DATATYPES:
            raise ParseError(
                "Illegal type: " + datatype, file=state["file"], line=state["line"]
            )
        if state.get("evs_parent"):
            # Inside ``BEGIN-VENDOR ... parent=NAME``: this attribute is an
            # EVS-VSA carried under the named extended wrapper. Key it as a
            # 4-tuple (extended_wrapper_code, evs_slot, vendor_id,
            # vendor_type) so encode/decode can find it without nesting.
            evs_marker = self.attributes[state["evs_parent"]]
            ext_wrapper = evs_marker.parent
            key = (
                ext_wrapper.code,
                evs_marker.code,
                self.vendors.get_forward(vendor),
                code,
            )
            is_sub_attribute = True
        elif vendor:
            if is_sub_attribute:
                key = (self.vendors.get_forward(vendor), parent_code, code)
            else:
                key = (self.vendors.get_forward(vendor), code)
        else:
            if is_sub_attribute:
                key = (parent_code, code)
            else:
                key = code

        self.attrindex.add(attribute, key)
        self.attributes[attribute] = Attribute(
            attribute,
            code,
            datatype,
            is_sub_attribute,
            vendor,
            encrypt=encrypt,
            has_tag=has_tag,
            concat=concat,
        )
        if datatype in ("tlv", "extended", "long-extended"):
            # Save the container so subsequent dotted-code sub-attributes
            # (e.g. ``ATTRIBUTE Frag-Status 241.1 integer``) can find their
            # parent regardless of whether the wrapper is a TLV or an
            # RFC 6929 extended attribute.
            state["tlvs"][code] = self.attributes[attribute]
        if state.get("evs_parent"):
            self.attributes[attribute].parent = self.attributes[state["evs_parent"]]
        elif is_sub_attribute:
            state["tlvs"][parent_code].sub_attributes[code] = attribute
            self.attributes[attribute].parent = state["tlvs"][parent_code]

    def __parse_value(self, state: dict, tokens: list, defer: bool) -> None:
        """Parse a VALUE line from a dictionary file."""
        if len(tokens) != 4:
            raise ParseError(
                "Incorrect number of tokens for value definition",
                file=state["file"],
                line=state["line"],
            )

        (attr, key, value) = tokens[1:]

        try:
            adef = self.attributes[attr]
        except KeyError:
            if defer:
                self.defer_parse.append((copy(state), copy(tokens)))
                return
            raise ParseError(
                "Value defined for unknown attribute " + attr,
                file=state["file"],
                line=state["line"],
            )

        if adef.type in ["integer", "signed", "short", "byte", "integer64"]:
            value = int(value, 0)
        value = tools.encode_attr(adef.type, value)
        self.attributes[attr].values.add(key, value)

    def __parse_vendor(self, state: dict, tokens: list) -> None:
        """Parse a VENDOR line, registering a new vendor."""
        if len(tokens) not in [3, 4]:
            raise ParseError(
                "Incorrect number of tokens for vendor definition",
                file=state["file"],
                line=state["line"],
            )

        vsa_format = VENDOR_FORMAT_DEFAULT
        if len(tokens) == 4:
            fmt = tokens[3].split("=")
            if fmt[0] != "format":
                raise ParseError(
                    "Unknown option '%s' for vendor definition" % (fmt[0]),
                    file=state["file"],
                    line=state["line"],
                )
            try:
                (_type, length) = tuple(int(a) for a in fmt[1].split(","))
                if _type not in [1, 2, 4] or length not in [0, 1, 2]:
                    raise ParseError(
                        "Unknown vendor format specification %s" % (fmt[1]),
                        file=state["file"],
                        line=state["line"],
                    )
                vsa_format = (_type, length)
            except ValueError:
                raise ParseError(
                    "Syntax error in vendor specification",
                    file=state["file"],
                    line=state["line"],
                )

        (vendorname, vendor) = tokens[1:3]
        try:
            vendor_id = int(vendor, 0)
        except ValueError:
            raise ParseError(
                "Invalid vendor id %r (expected an integer literal)" % (vendor,),
                file=state["file"],
                line=state["line"],
            )
        # RFC 2865 §5.26: the SMI Network Management Private Enterprise
        # Code is an unsigned 24-bit value. Anything outside that range
        # would silently corrupt the VSA encoder.
        if not 0 <= vendor_id <= 0xFFFFFF:
            raise ParseError(
                "Vendor id %d out of range (expected 0..0xFFFFFF)" % vendor_id,
                file=state["file"],
                line=state["line"],
            )
        self.vendors.add(vendorname, vendor_id)
        if vsa_format != VENDOR_FORMAT_DEFAULT:
            self.vendor_formats[vendor_id] = vsa_format

    def __parse_begin_vendor(self, state: dict, tokens: list) -> None:
        """Start a block of attributes for a specific vendor.

        Accepts the FreeRADIUS ``parent=NAME`` form which scopes the block
        as an RFC 6929 EVS region: every ATTRIBUTE inside is an EVS-VSA
        carried under the named extended wrapper.
        """
        if len(tokens) not in (2, 3):
            raise ParseError(
                "Incorrect number of tokens for begin-vendor statement",
                file=state["file"],
                line=state["line"],
            )

        vendor = tokens[1]

        if not self.vendors.has_forward(vendor):
            raise ParseError(
                "Unknown vendor %s in begin-vendor statement" % vendor,
                file=state["file"],
                line=state["line"],
            )

        evs_parent = None
        if len(tokens) == 3:
            opt = tokens[2]
            if not opt.startswith("parent="):
                raise ParseError(
                    "Unknown option %s in begin-vendor statement" % opt,
                    file=state["file"],
                    line=state["line"],
                )
            evs_parent = opt.split("=", 1)[1]
            marker = self.attributes.get(evs_parent)
            if marker is None:
                raise ParseError(
                    "Unknown parent %s in begin-vendor statement" % evs_parent,
                    file=state["file"],
                    line=state["line"],
                )
            if marker.type != "evs":
                raise ParseError(
                    "begin-vendor parent %s must be of type evs (got %s)"
                    % (evs_parent, marker.type),
                    file=state["file"],
                    line=state["line"],
                )

        state["vendor"] = vendor
        state["evs_parent"] = evs_parent

    def __parse_end_vendor(self, state: dict, tokens: list):
        """End a block of vendor-specific attributes."""
        if len(tokens) != 2:
            raise ParseError(
                "Incorrect number of tokens for end-vendor statement",
                file=state["file"],
                line=state["line"],
            )

        vendor = tokens[1]

        if state["vendor"] != vendor:
            raise ParseError(
                "Ending non-open vendor" + vendor,
                file=state["file"],
                line=state["line"],
            )
        state["vendor"] = ""
        state["evs_parent"] = None

    def read_dictionary(self, file: str) -> None:
        """Parse a dictionary file.
        Reads a RADIUS dictionary file and merges its contents into the
        class instance.

        Args:
            file (str | io): Name of dictionary file to parse or a file-like object
        """

        fil = dictfile.DictFile(file, include_base_dir=self._include_base_dir)

        state: Dict[str, Any] = {}
        state["vendor"] = ""
        state["evs_parent"] = None
        state["tlvs"] = {}
        self.defer_parse = []
        for line in fil:
            state["file"] = fil.file()
            state["line"] = fil.line()
            line = line.split("#", 1)[0].strip()

            tokens = line.split()
            if not tokens:
                continue

            key = tokens[0].upper()
            if key == "ATTRIBUTE":
                self.__parse_attribute(state, tokens)
            elif key == "VALUE":
                self.__parse_value(state, tokens, True)
            elif key == "VENDOR":
                self.__parse_vendor(state, tokens)
            elif key == "BEGIN-VENDOR":
                self.__parse_begin_vendor(state, tokens)
            elif key == "END-VENDOR":
                self.__parse_end_vendor(state, tokens)

        for state, tokens in self.defer_parse:
            key = tokens[0].upper()
            if key == "VALUE":
                self.__parse_value(state, tokens, False)
        self.defer_parse = []
