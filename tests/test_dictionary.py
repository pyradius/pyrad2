import operator
import os
import tempfile
from io import StringIO

import pytest

from pyrad2.dictfile import DictFile
from pyrad2.dictionary import Attribute, Dictionary, ParseError
from pyrad2.tools import decode_attr

from .base import TEST_ROOT_PATH


class TestAttribute:
    def test_invalid_data_type(self):
        with pytest.raises(ValueError):
            Attribute("name", "code", "datatype")

    def test_construction_parameters(self):
        attr = Attribute("name", "code", "integer", False, "vendor")
        assert attr.name == "name"
        assert attr.code == "code"
        assert attr.type == "integer"
        assert attr.is_sub_attribute is False
        assert attr.vendor == "vendor"
        assert len(attr.values) == 0
        assert len(attr.sub_attributes) == 0

    def test_named_construction_parameters(self):
        attr = Attribute(name="name", code="code", datatype="integer", vendor="vendor")
        assert attr.name == "name"
        assert attr.code == "code"
        assert attr.type == "integer"
        assert attr.vendor == "vendor"
        assert len(attr.values) == 0

    def test_values(self):
        attr = Attribute(
            "name",
            "code",
            "integer",
            False,
            "vendor",
            dict(pie="custard", shake="vanilla"),
        )
        assert len(attr.values) == 2
        assert attr.values["shake"] == "vanilla"


class TestDictionaryInterface:
    def test_empty_dictionary(self):
        d = Dictionary()
        assert len(d) == 0

    def test_containment(self):
        d = Dictionary()
        assert "test" not in d
        assert d.has_key("test") is False
        d.attributes["test"] = "dummy"
        assert "test" in d
        assert d.has_key("test") is True

    def test_readonly_container(self):
        d = Dictionary()
        with pytest.raises(TypeError):
            operator.setitem(d, "test", "dummy")
        with pytest.raises(AttributeError):
            operator.attrgetter("clear")(d)
        with pytest.raises(AttributeError):
            operator.attrgetter("update")(d)


class TestDictionaryParsing:
    simple_dict_values = [
        ("Test-String", 1, "string"),
        ("Test-Octets", 2, "octets"),
        ("Test-Integer", 0x03, "integer"),
        ("Test-Ip-Address", 4, "ipaddr"),
        ("Test-Ipv6-Address", 5, "ipv6addr"),
        ("Test-If-Id", 6, "ifid"),
        ("Test-Date", 7, "date"),
        ("Test-Abinary", 8, "abinary"),
        ("Test-Tlv", 9, "tlv"),
        ("Test-Tlv-Str", 1, "string"),
        ("Test-Tlv-Int", 2, "integer"),
        ("Test-Integer64", 10, "integer64"),
        ("Test-Integer64-Hex", 10, "integer64"),
        ("Test-Integer64-Oct", 10, "integer64"),
    ]

    def setup_method(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "simple"))

    def test_parse_empty_dictionary(self):
        d = Dictionary(StringIO(""))
        assert len(d) == 0

    def test_parse_multiple_dictionaries(self):
        d = Dictionary(StringIO(""))
        assert len(d) == 0
        one = StringIO("ATTRIBUTE Test-First 1 string")
        two = StringIO("ATTRIBUTE Test-Second 2 string")
        d = Dictionary(StringIO(""), one, two)
        assert len(d) == 2

    def test_parse_simple_dictionary(self):
        assert len(self.dict) == len(self.simple_dict_values)
        for name, code, type_ in self.simple_dict_values:
            attr = self.dict[name]
            assert attr.code == code
            assert attr.type == type_

    def test_attribute_too_few_columns_error(self):
        with pytest.raises(ParseError, match="attribute"):
            self.dict.read_dictionary(StringIO("ATTRIBUTE Oops-Too-Few-Columns"))

    def test_attribute_unknown_type_error(self):
        with pytest.raises(ParseError, match="dummy"):
            self.dict.read_dictionary(StringIO("ATTRIBUTE Test-Type 1 dummy"))

    def test_attribute_unknown_vendor_error(self):
        with pytest.raises(ParseError, match="Simplon"):
            self.dict.read_dictionary(StringIO("ATTRIBUTE Test-Type 1 Simplon"))

    def test_attribute_options(self):
        self.dict.read_dictionary(
            StringIO("ATTRIBUTE Option-Type 1 string has_tag,encrypt=1")
        )
        assert self.dict["Option-Type"].has_tag is True
        assert self.dict["Option-Type"].encrypt == 1
        assert self.dict["Option-Type"].concat is False

    def test_attribute_concat_option(self):
        # FreeRADIUS-style concat option keeps the attribute defined
        # instead of silently dropping it (the old behaviour).
        self.dict.read_dictionary(StringIO("ATTRIBUTE Long-Octets 30 octets concat"))
        assert self.dict["Long-Octets"].concat is True
        assert self.dict["Long-Octets"].type == "octets"
        assert self.dict["Long-Octets"].code == 30

    def test_attribute_concat_combined_with_other_options(self):
        self.dict.read_dictionary(
            StringIO("ATTRIBUTE Frag-Octets 31 octets has_tag,concat,encrypt=2")
        )
        attr = self.dict["Frag-Octets"]
        assert attr.has_tag
        assert attr.concat
        assert attr.encrypt == 2

    def test_attribute_encryption_error(self):
        with pytest.raises(ParseError, match="encrypt"):
            self.dict.read_dictionary(
                StringIO("ATTRIBUTE Test-Type 1 string encrypt=4")
            )

    def test_value_too_few_columns_error(self):
        with pytest.raises(ParseError, match="value"):
            self.dict.read_dictionary(StringIO("VALUE Oops-Too-Few-Columns"))

    def test_value_for_unknown_attribute_error(self):
        with pytest.raises(ParseError, match="unknown attribute"):
            self.dict.read_dictionary(StringIO("VALUE Test-Attribute Test-Text 1"))

    def test_integer_value_parsing(self):
        assert len(self.dict["Test-Integer"].values) == 0
        self.dict.read_dictionary(StringIO("VALUE Test-Integer Value-Six 5"))
        assert len(self.dict["Test-Integer"].values) == 1
        assert (
            decode_attr("integer", self.dict["Test-Integer"].values["Value-Six"]) == 5
        )

    def test_integer64_value_parsing(self):
        assert len(self.dict["Test-Integer64"].values) == 0
        self.dict.read_dictionary(StringIO("VALUE Test-Integer64 Value-Six 5"))
        assert len(self.dict["Test-Integer64"].values) == 1
        assert (
            decode_attr("integer64", self.dict["Test-Integer64"].values["Value-Six"])
            == 5
        )

    def test_string_value_parsing(self):
        assert len(self.dict["Test-String"].values) == 0
        self.dict.read_dictionary(
            StringIO("VALUE Test-String Value-Custard custardpie")
        )
        assert len(self.dict["Test-String"].values) == 1
        assert (
            decode_attr("string", self.dict["Test-String"].values["Value-Custard"])
            == "custardpie"
        )

    def test_octet_value_parsing(self):
        assert len(self.dict["Test-Octets"].values) == 0
        self.dict.read_dictionary(
            StringIO(
                "ATTRIBUTE Test-Octets 1 octets\n"
                "VALUE Test-Octets Value-A 65\n"  # "A"
                "VALUE Test-Octets Value-B 0x42\n"
            )
        )  # "B"
        assert len(self.dict["Test-Octets"].values) == 2
        assert decode_attr("octets", self.dict["Test-Octets"].values["Value-A"]) == b"A"
        assert decode_attr("octets", self.dict["Test-Octets"].values["Value-B"]) == b"B"

    def test_tlv_parsing(self):
        assert len(self.dict["Test-Tlv"].sub_attributes) == 2
        assert self.dict["Test-Tlv"].sub_attributes == {
            1: "Test-Tlv-Str",
            2: "Test-Tlv-Int",
        }

    def test_sub_tlv_parsing(self, full_dictionary):
        for attr, _, _ in self.simple_dict_values:
            if attr.startswith("Test-Tlv-"):
                assert self.dict[attr].is_sub_attribute is True
                assert self.dict[attr].parent == self.dict["Test-Tlv"]
            else:
                assert self.dict[attr].is_sub_attribute is False
                assert self.dict[attr].parent is None

        # tlv with vendor
        full_dict = full_dictionary
        assert full_dict["Simplon-Tlv-Str"].is_sub_attribute is True
        assert full_dict["Simplon-Tlv-Str"].parent == full_dict["Simplon-Tlv"]
        assert full_dict["Simplon-Tlv-Int"].is_sub_attribute is True
        assert full_dict["Simplon-Tlv-Int"].parent == full_dict["Simplon-Tlv"]

    def test_vendor_too_few_columns_error(self):
        with pytest.raises(ParseError, match="vendor"):
            self.dict.read_dictionary(StringIO("VENDOR Simplon"))

    def test_vendor_parsing(self):
        with pytest.raises(ParseError):
            self.dict.read_dictionary(StringIO("ATTRIBUTE Test-Type 1 integer Simplon"))
        self.dict.read_dictionary(StringIO("VENDOR Simplon 42"))
        assert self.dict.vendors["Simplon"] == 42
        self.dict.read_dictionary(StringIO("ATTRIBUTE Test-Type 1 integer Simplon"))
        assert self.dict.attrindex["Test-Type"] == (42, 1)

    def test_vendor_option_error(self):
        with pytest.raises(ParseError):
            self.dict.read_dictionary(StringIO("ATTRIBUTE Test-Type 1 integer Simplon"))
        with pytest.raises(ParseError, match="option"):
            self.dict.read_dictionary(StringIO("VENDOR Simplon 42 badoption"))

    def test_vendor_format_error(self):
        with pytest.raises(ParseError):
            self.dict.read_dictionary(StringIO("ATTRIBUTE Test-Type 1 integer Simplon"))
        with pytest.raises(ParseError, match="format"):
            self.dict.read_dictionary(StringIO("VENDOR Simplon 42 format=5,4"))

    def test_vendor_format_syntax_error(self):
        with pytest.raises(ParseError):
            self.dict.read_dictionary(StringIO("ATTRIBUTE Test-Type 1 integer Simplon"))
        with pytest.raises(ParseError, match="Syntax"):
            self.dict.read_dictionary(StringIO("VENDOR Simplon 42 format=a,1"))

    def test_extended_parent_and_sub_attribute(self):
        # RFC 6929: parent 241 declared as ``extended``, with a sub-attribute
        # under the dotted-code form ``241.1``.
        self.dict.read_dictionary(
            StringIO(
                "ATTRIBUTE Extended-Attribute-1 241 extended\n"
                "ATTRIBUTE Frag-Status 241.1 integer\n"
            )
        )
        parent = self.dict["Extended-Attribute-1"]
        assert parent.type == "extended"
        assert parent.code == 241
        sub = self.dict["Frag-Status"]
        assert sub.is_sub_attribute
        assert sub.code == 1
        assert sub.parent is parent
        assert parent.sub_attributes == {1: "Frag-Status"}

    def test_long_extended_parent_and_sub_attribute(self):
        self.dict.read_dictionary(
            StringIO(
                "ATTRIBUTE Extended-Attribute-5 245 long-extended\n"
                "ATTRIBUTE WiMAX-Blob 245.1 octets\n"
            )
        )
        parent = self.dict["Extended-Attribute-5"]
        assert parent.type == "long-extended"
        assert parent.code == 245
        sub = self.dict["WiMAX-Blob"]
        assert sub.is_sub_attribute
        assert sub.parent is parent

    def test_evs_parser_stores_four_tuple_key(self):
        # RFC 6929 §2.3 — EVS-VSA. The marker lives at 241.26 with type evs,
        # then BEGIN-VENDOR parent= scopes the vendor block beneath it.
        self.dict.read_dictionary(
            StringIO(
                "ATTRIBUTE Extended-Attribute-1 241 extended\n"
                "ATTRIBUTE Extended-Vendor-Specific-1 241.26 evs\n"
                "VENDOR Example 12345\n"
                "BEGIN-VENDOR Example parent=Extended-Vendor-Specific-1\n"
                "ATTRIBUTE Example-Attr-1 1 string\n"
                "ATTRIBUTE Example-Attr-2 2 integer\n"
                "END-VENDOR Example\n"
            )
        )
        # The vendor attributes index under the canonical 4-tuple.
        assert self.dict.attrindex["Example-Attr-1"] == (241, 26, 12345, 1)
        assert self.dict.attrindex["Example-Attr-2"] == (241, 26, 12345, 2)
        # And their parent points back at the EVS marker.
        marker = self.dict["Extended-Vendor-Specific-1"]
        assert marker.type == "evs"
        assert self.dict["Example-Attr-1"].parent is marker
        assert self.dict["Example-Attr-1"].vendor == "Example"
        assert self.dict["Example-Attr-1"].is_sub_attribute

    def test_evs_rejects_non_evs_parent(self):
        # parent= must refer to an attribute whose type is "evs".
        with pytest.raises(ParseError, match="(?i)evs"):
            self.dict.read_dictionary(
                StringIO(
                    "ATTRIBUTE Extended-Attribute-1 241 extended\n"
                    "ATTRIBUTE Not-Evs 241.7 integer\n"
                    "VENDOR Example 12345\n"
                    "BEGIN-VENDOR Example parent=Not-Evs\n"
                )
            )

    def test_vendor_format_stored_and_retrievable(self):
        # Default format is (1, 1, False) when no format= is declared.
        self.dict.read_dictionary(StringIO("VENDOR Cisco 9"))
        assert self.dict.vendor_format(9) == (1, 1, False)

        # Explicit format= persists on the dictionary.
        self.dict.read_dictionary(StringIO("VENDOR USR 429 format=4,0"))
        assert self.dict.vendor_format(429) == (4, 0, False)

        self.dict.read_dictionary(StringIO("VENDOR Big-Type 100 format=2,1"))
        assert self.dict.vendor_format(100) == (2, 1, False)

        # ``,c`` opts the vendor into RFC 5904 long-packed VSA encoding.
        self.dict.read_dictionary(StringIO("VENDOR WiMAX 24757 format=1,1,c"))
        assert self.dict.vendor_format(24757) == (1, 1, True)

        # Unknown vendor ids fall back to the default.
        assert self.dict.vendor_format(99999) == (1, 1, False)

    def test_begin_vendor_too_few_columns(self):
        with pytest.raises(ParseError, match="begin-vendor"):
            self.dict.read_dictionary(StringIO("BEGIN-VENDOR"))

    def test_begin_vendor_unknown_vendor(self):
        with pytest.raises(ParseError, match="Simplon"):
            self.dict.read_dictionary(StringIO("BEGIN-VENDOR Simplon"))

    def test_begin_vendor_parsing(self):
        self.dict.read_dictionary(
            StringIO(
                "VENDOR Simplon 42\nBEGIN-VENDOR Simplon\nATTRIBUTE Test-Type 1 integer"
            )
        )
        assert self.dict.attrindex["Test-Type"] == (42, 1)

    def test_end_vendor_unknown_vendor(self):
        with pytest.raises(ParseError, match="end-vendor"):
            self.dict.read_dictionary(StringIO("END-VENDOR"))

    def test_end_vendor_unbalanced(self):
        with pytest.raises(ParseError, match="Oops"):
            self.dict.read_dictionary(
                StringIO("VENDOR Simplon 42\nBEGIN-VENDOR Simplon\nEND-VENDOR Oops\n")
            )

    def test_end_vendor_parsing(self):
        self.dict.read_dictionary(
            StringIO(
                "VENDOR Simplon 42\n"
                "BEGIN-VENDOR Simplon\n"
                "END-VENDOR Simplon\n"
                "ATTRIBUTE Test-Type 1 integer"
            )
        )
        assert self.dict.attrindex["Test-Type"] == 1

    def test_include(self):
        with pytest.raises(OSError, match="this_file_does_not_exist"):
            self.dict.read_dictionary(
                StringIO(
                    "$INCLUDE this_file_does_not_exist\n"
                    "VENDOR Simplon 42\n"
                    "BEGIN-VENDOR Simplon\n"
                    "END-VENDOR Simplon\n"
                    "ATTRIBUTE Test-Type 1 integer"
                )
            )

    def test_dict_file_post_parse(self):
        f = DictFile(StringIO("VENDOR Simplon 42\n"))
        for _ in f:
            pass
        assert f.file() == ""
        assert f.line() == -1

    def test_dict_file_parse_error(self):
        tmpdict = Dictionary()
        with pytest.raises(ParseError, match="dictfiletest"):
            tmpdict.read_dictionary(os.path.join(self.path, "dictfiletest"))


class TestIncludeSandboxing:
    """Regression coverage for the $INCLUDE path-traversal hardening."""

    def test_absolute_include_outside_base_is_rejected(self):
        # $INCLUDE /etc/passwd from an untrusted dictionary used to read
        # whatever the process had access to. Now it must be rejected.
        with pytest.raises(ParseError, match="escapes the dictionary base"):
            Dictionary(
                StringIO("$INCLUDE /etc/passwd\n"),
                include_base_dir=TEST_ROOT_PATH,
            )

    def test_relative_traversal_is_rejected(self):
        # ../ traversal also escapes the trusted base.
        with pytest.raises(ParseError, match="escapes the dictionary base"):
            Dictionary(
                StringIO("$INCLUDE ../../../etc/passwd\n"),
                include_base_dir=TEST_ROOT_PATH,
            )

    def test_legitimate_relative_include_still_works(self, radsec_dictionary):
        # Sanity: the canonical FreeRADIUS-style sibling include still
        # resolves under the trusted base.
        assert len(radsec_dictionary) > 0


class TestVendorIdRange:
    """Regression coverage for the vendor-id range check."""

    def test_negative_vendor_id_is_rejected(self):
        with pytest.raises(ParseError, match="out of range"):
            Dictionary(StringIO("VENDOR Bogus -1\n"))

    def test_overflow_vendor_id_is_rejected(self):
        # 0x1000000 is one past the 24-bit ceiling.
        with pytest.raises(ParseError, match="out of range"):
            Dictionary(StringIO("VENDOR Bogus 0x1000000\n"))

    def test_non_integer_vendor_id_is_rejected(self):
        with pytest.raises(ParseError, match="Invalid vendor id"):
            Dictionary(StringIO("VENDOR Bogus notanumber\n"))

    def test_valid_vendor_id_is_accepted(self):
        d = Dictionary(StringIO("VENDOR Simplon 0xFFFFFF\n"))
        assert d.vendors["Simplon"] == 0xFFFFFF


class TestParseErrorMetadata:
    """Regression coverage for the ParseError signature tightening (H12)."""

    def test_filename_surfaces_in_error_message(self):
        # Pre-fix this branch passed ``name=state["file"]`` to ParseError,
        # which silently dropped it.
        with pytest.raises(ParseError) as exc_info:
            Dictionary(StringIO("ATTRIBUTE TooFew\n"))
        assert exc_info.value.file == ""  # StringIO has no filename
        assert "Incorrect number of tokens" in (exc_info.value.msg or "")

    def test_filename_surfaces_for_file_input(self):
        # The same error from a real file must carry the file name.
        with tempfile.NamedTemporaryFile("w", suffix=".dict", delete=False) as f:
            f.write("ATTRIBUTE TooFew\n")
            fname = f.name
        try:
            with pytest.raises(ParseError) as exc_info:
                Dictionary(fname)
            assert os.path.basename(fname) == exc_info.value.file
            assert os.path.basename(fname) in str(exc_info.value)
        finally:
            os.unlink(fname)

    def test_unknown_kwargs_are_rejected(self):
        # The old **data signature silently swallowed name=. The tightened
        # signature must reject it so future drift is impossible.
        with pytest.raises(TypeError):
            ParseError("oops", name="ignored")  # type: ignore[call-arg]
