import operator
import os
import unittest
from io import StringIO

from pyrad2.dictfile import DictFile
from pyrad2.dictionary import Attribute, Dictionary, ParseError
from pyrad2.tools import decode_attr

from .base import TEST_ROOT_PATH


class AttributeTests(unittest.TestCase):
    def testInvalidDataType(self):
        self.assertRaises(ValueError, Attribute, "name", "code", "datatype")

    def testConstructionParameters(self):
        attr = Attribute("name", "code", "integer", False, "vendor")
        self.assertEqual(attr.name, "name")
        self.assertEqual(attr.code, "code")
        self.assertEqual(attr.type, "integer")
        self.assertEqual(attr.is_sub_attribute, False)
        self.assertEqual(attr.vendor, "vendor")
        self.assertEqual(len(attr.values), 0)
        self.assertEqual(len(attr.sub_attributes), 0)

    def testNamedConstructionParameters(self):
        attr = Attribute(name="name", code="code", datatype="integer", vendor="vendor")
        self.assertEqual(attr.name, "name")
        self.assertEqual(attr.code, "code")
        self.assertEqual(attr.type, "integer")
        self.assertEqual(attr.vendor, "vendor")
        self.assertEqual(len(attr.values), 0)

    def testValues(self):
        attr = Attribute(
            "name",
            "code",
            "integer",
            False,
            "vendor",
            dict(pie="custard", shake="vanilla"),
        )
        self.assertEqual(len(attr.values), 2)
        self.assertEqual(attr.values["shake"], "vanilla")


class DictionaryInterfaceTests(unittest.TestCase):
    def testEmptyDictionary(self):
        dict = Dictionary()
        self.assertEqual(len(dict), 0)

    def testContainment(self):
        dict = Dictionary()
        self.assertEqual("test" in dict, False)
        self.assertEqual(dict.has_key("test"), False)
        dict.attributes["test"] = "dummy"
        self.assertEqual("test" in dict, True)
        self.assertEqual(dict.has_key("test"), True)

    def testReadonlyContainer(self):
        dict = Dictionary()
        self.assertRaises(TypeError, operator.setitem, dict, "test", "dummy")
        self.assertRaises(AttributeError, operator.attrgetter("clear"), dict)
        self.assertRaises(AttributeError, operator.attrgetter("update"), dict)


class DictionaryParsingTests(unittest.TestCase):
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

    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "simple"))

    def testParseEmptyDictionary(self):
        dict = Dictionary(StringIO(""))
        self.assertEqual(len(dict), 0)

    def testParseMultipleDictionaries(self):
        dict = Dictionary(StringIO(""))
        self.assertEqual(len(dict), 0)
        one = StringIO("ATTRIBUTE Test-First 1 string")
        two = StringIO("ATTRIBUTE Test-Second 2 string")
        dict = Dictionary(StringIO(""), one, two)
        self.assertEqual(len(dict), 2)

    def testParseSimpleDictionary(self):
        self.assertEqual(len(self.dict), len(self.simple_dict_values))
        for attr, code, type in self.simple_dict_values:
            attr = self.dict[attr]
            self.assertEqual(attr.code, code)
            self.assertEqual(attr.type, type)

    def testAttributeTooFewColumnsError(self):
        try:
            self.dict.read_dictionary(StringIO("ATTRIBUTE Oops-Too-Few-Columns"))
        except ParseError as e:
            self.assertEqual("attribute" in str(e), True)
        else:
            self.fail()

    def testAttributeUnknownTypeError(self):
        try:
            self.dict.read_dictionary(StringIO("ATTRIBUTE Test-Type 1 dummy"))
        except ParseError as e:
            self.assertEqual("dummy" in str(e), True)
        else:
            self.fail()

    def testAttributeUnknownVendorError(self):
        try:
            self.dict.read_dictionary(StringIO("ATTRIBUTE Test-Type 1 Simplon"))
        except ParseError as e:
            self.assertEqual("Simplon" in str(e), True)
        else:
            self.fail()

    def testAttributeOptions(self):
        self.dict.read_dictionary(
            StringIO("ATTRIBUTE Option-Type 1 string has_tag,encrypt=1")
        )
        self.assertEqual(self.dict["Option-Type"].has_tag, True)
        self.assertEqual(self.dict["Option-Type"].encrypt, 1)
        self.assertEqual(self.dict["Option-Type"].concat, False)

    def testAttributeConcatOption(self):
        # FreeRADIUS-style concat option keeps the attribute defined
        # instead of silently dropping it (the old behaviour).
        self.dict.read_dictionary(
            StringIO("ATTRIBUTE Long-Octets 30 octets concat")
        )
        self.assertEqual(self.dict["Long-Octets"].concat, True)
        self.assertEqual(self.dict["Long-Octets"].type, "octets")
        self.assertEqual(self.dict["Long-Octets"].code, 30)

    def testAttributeConcatCombinedWithOtherOptions(self):
        self.dict.read_dictionary(
            StringIO("ATTRIBUTE Frag-Octets 31 octets has_tag,concat,encrypt=2")
        )
        attr = self.dict["Frag-Octets"]
        self.assertTrue(attr.has_tag)
        self.assertTrue(attr.concat)
        self.assertEqual(attr.encrypt, 2)

    def testAttributeEncryptionError(self):
        try:
            self.dict.read_dictionary(
                StringIO("ATTRIBUTE Test-Type 1 string encrypt=4")
            )
        except ParseError as e:
            self.assertEqual("encrypt" in str(e), True)
        else:
            self.fail()

    def testValueTooFewColumnsError(self):
        try:
            self.dict.read_dictionary(StringIO("VALUE Oops-Too-Few-Columns"))
        except ParseError as e:
            self.assertEqual("value" in str(e), True)
        else:
            self.fail()

    def testValueForUnknownAttributeError(self):
        try:
            self.dict.read_dictionary(StringIO("VALUE Test-Attribute Test-Text 1"))
        except ParseError as e:
            self.assertEqual("unknown attribute" in str(e), True)
        else:
            self.fail()

    def testIntegerValueParsing(self):
        self.assertEqual(len(self.dict["Test-Integer"].values), 0)
        self.dict.read_dictionary(StringIO("VALUE Test-Integer Value-Six 5"))
        self.assertEqual(len(self.dict["Test-Integer"].values), 1)
        self.assertEqual(
            decode_attr("integer", self.dict["Test-Integer"].values["Value-Six"]), 5
        )

    def testInteger64ValueParsing(self):
        self.assertEqual(len(self.dict["Test-Integer64"].values), 0)
        self.dict.read_dictionary(StringIO("VALUE Test-Integer64 Value-Six 5"))
        self.assertEqual(len(self.dict["Test-Integer64"].values), 1)
        self.assertEqual(
            decode_attr("integer64", self.dict["Test-Integer64"].values["Value-Six"]), 5
        )

    def testStringValueParsing(self):
        self.assertEqual(len(self.dict["Test-String"].values), 0)
        self.dict.read_dictionary(
            StringIO("VALUE Test-String Value-Custard custardpie")
        )
        self.assertEqual(len(self.dict["Test-String"].values), 1)
        self.assertEqual(
            decode_attr("string", self.dict["Test-String"].values["Value-Custard"]),
            "custardpie",
        )

    def testOctetValueParsing(self):
        self.assertEqual(len(self.dict["Test-Octets"].values), 0)
        self.dict.read_dictionary(
            StringIO(
                "ATTRIBUTE Test-Octets 1 octets\n"
                "VALUE Test-Octets Value-A 65\n"  # "A"
                "VALUE Test-Octets Value-B 0x42\n"
            )
        )  # "B"
        self.assertEqual(len(self.dict["Test-Octets"].values), 2)
        self.assertEqual(
            decode_attr("octets", self.dict["Test-Octets"].values["Value-A"]), b"A"
        )
        self.assertEqual(
            decode_attr("octets", self.dict["Test-Octets"].values["Value-B"]), b"B"
        )

    def testTlvParsing(self):
        self.assertEqual(len(self.dict["Test-Tlv"].sub_attributes), 2)
        self.assertEqual(
            self.dict["Test-Tlv"].sub_attributes, {1: "Test-Tlv-Str", 2: "Test-Tlv-Int"}
        )

    def testSubTlvParsing(self):
        for attr, _, _ in self.simple_dict_values:
            if attr.startswith("Test-Tlv-"):
                self.assertEqual(self.dict[attr].is_sub_attribute, True)
                self.assertEqual(self.dict[attr].parent, self.dict["Test-Tlv"])
            else:
                self.assertEqual(self.dict[attr].is_sub_attribute, False)
                self.assertEqual(self.dict[attr].parent, None)

        # tlv with vendor
        full_dict = Dictionary(os.path.join(self.path, "full"))
        self.assertEqual(full_dict["Simplon-Tlv-Str"].is_sub_attribute, True)
        self.assertEqual(full_dict["Simplon-Tlv-Str"].parent, full_dict["Simplon-Tlv"])
        self.assertEqual(full_dict["Simplon-Tlv-Int"].is_sub_attribute, True)
        self.assertEqual(full_dict["Simplon-Tlv-Int"].parent, full_dict["Simplon-Tlv"])

    def testVenderTooFewColumnsError(self):
        try:
            self.dict.read_dictionary(StringIO("VENDOR Simplon"))
        except ParseError as e:
            self.assertEqual("vendor" in str(e), True)
        else:
            self.fail()

    def testVendorParsing(self):
        self.assertRaises(
            ParseError,
            self.dict.read_dictionary,
            StringIO("ATTRIBUTE Test-Type 1 integer Simplon"),
        )
        self.dict.read_dictionary(StringIO("VENDOR Simplon 42"))
        self.assertEqual(self.dict.vendors["Simplon"], 42)
        self.dict.read_dictionary(StringIO("ATTRIBUTE Test-Type 1 integer Simplon"))
        self.assertEqual(self.dict.attrindex["Test-Type"], (42, 1))

    def testVendorOptionError(self):
        self.assertRaises(
            ParseError,
            self.dict.read_dictionary,
            StringIO("ATTRIBUTE Test-Type 1 integer Simplon"),
        )
        try:
            self.dict.read_dictionary(StringIO("VENDOR Simplon 42 badoption"))
        except ParseError as e:
            self.assertEqual("option" in str(e), True)
        else:
            self.fail()

    def testVendorFormatError(self):
        self.assertRaises(
            ParseError,
            self.dict.read_dictionary,
            StringIO("ATTRIBUTE Test-Type 1 integer Simplon"),
        )
        try:
            self.dict.read_dictionary(StringIO("VENDOR Simplon 42 format=5,4"))
        except ParseError as e:
            self.assertEqual("format" in str(e), True)
        else:
            self.fail()

    def testVendorFormatSyntaxError(self):
        self.assertRaises(
            ParseError,
            self.dict.read_dictionary,
            StringIO("ATTRIBUTE Test-Type 1 integer Simplon"),
        )
        try:
            self.dict.read_dictionary(StringIO("VENDOR Simplon 42 format=a,1"))
        except ParseError as e:
            self.assertEqual("Syntax" in str(e), True)
        else:
            self.fail()

    def testExtendedParentAndSubAttribute(self):
        # RFC 6929: parent 241 declared as ``extended``, with a sub-attribute
        # under the dotted-code form ``241.1``.
        self.dict.read_dictionary(
            StringIO(
                "ATTRIBUTE Extended-Attribute-1 241 extended\n"
                "ATTRIBUTE Frag-Status 241.1 integer\n"
            )
        )
        parent = self.dict["Extended-Attribute-1"]
        self.assertEqual(parent.type, "extended")
        self.assertEqual(parent.code, 241)
        sub = self.dict["Frag-Status"]
        self.assertTrue(sub.is_sub_attribute)
        self.assertEqual(sub.code, 1)
        self.assertIs(sub.parent, parent)
        self.assertEqual(parent.sub_attributes, {1: "Frag-Status"})

    def testLongExtendedParentAndSubAttribute(self):
        self.dict.read_dictionary(
            StringIO(
                "ATTRIBUTE Extended-Attribute-5 245 long-extended\n"
                "ATTRIBUTE WiMAX-Blob 245.1 octets\n"
            )
        )
        parent = self.dict["Extended-Attribute-5"]
        self.assertEqual(parent.type, "long-extended")
        self.assertEqual(parent.code, 245)
        sub = self.dict["WiMAX-Blob"]
        self.assertTrue(sub.is_sub_attribute)
        self.assertIs(sub.parent, parent)

    def testEvsParserStoresFourTupleKey(self):
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
        self.assertEqual(self.dict.attrindex["Example-Attr-1"], (241, 26, 12345, 1))
        self.assertEqual(self.dict.attrindex["Example-Attr-2"], (241, 26, 12345, 2))
        # And their parent points back at the EVS marker.
        marker = self.dict["Extended-Vendor-Specific-1"]
        self.assertEqual(marker.type, "evs")
        self.assertIs(self.dict["Example-Attr-1"].parent, marker)
        self.assertEqual(self.dict["Example-Attr-1"].vendor, "Example")
        self.assertTrue(self.dict["Example-Attr-1"].is_sub_attribute)

    def testEvsRejectsNonEvsParent(self):
        # parent= must refer to an attribute whose type is "evs".
        try:
            self.dict.read_dictionary(
                StringIO(
                    "ATTRIBUTE Extended-Attribute-1 241 extended\n"
                    "ATTRIBUTE Not-Evs 241.7 integer\n"
                    "VENDOR Example 12345\n"
                    "BEGIN-VENDOR Example parent=Not-Evs\n"
                )
            )
        except ParseError as e:
            self.assertIn("evs", str(e).lower())
        else:
            self.fail("expected ParseError for non-evs parent")

    def testVendorFormatStoredAndRetrievable(self):
        # Default format is (1, 1) when no format= is declared.
        self.dict.read_dictionary(StringIO("VENDOR Cisco 9"))
        self.assertEqual(self.dict.vendor_format(9), (1, 1))

        # Explicit format= persists on the dictionary.
        self.dict.read_dictionary(StringIO("VENDOR USR 429 format=4,0"))
        self.assertEqual(self.dict.vendor_format(429), (4, 0))

        self.dict.read_dictionary(StringIO("VENDOR Big-Type 100 format=2,1"))
        self.assertEqual(self.dict.vendor_format(100), (2, 1))

        # Unknown vendor ids fall back to the default.
        self.assertEqual(self.dict.vendor_format(99999), (1, 1))

    def testBeginVendorTooFewColumns(self):
        try:
            self.dict.read_dictionary(StringIO("BEGIN-VENDOR"))
        except ParseError as e:
            self.assertEqual("begin-vendor" in str(e), True)
        else:
            self.fail()

    def testBeginVendorUnknownVendor(self):
        try:
            self.dict.read_dictionary(StringIO("BEGIN-VENDOR Simplon"))
        except ParseError as e:
            self.assertEqual("Simplon" in str(e), True)
        else:
            self.fail()

    def testBeginVendorParsing(self):
        self.dict.read_dictionary(
            StringIO(
                "VENDOR Simplon 42\nBEGIN-VENDOR Simplon\nATTRIBUTE Test-Type 1 integer"
            )
        )
        self.assertEqual(self.dict.attrindex["Test-Type"], (42, 1))

    def testEndVendorUnknownVendor(self):
        try:
            self.dict.read_dictionary(StringIO("END-VENDOR"))
        except ParseError as e:
            self.assertEqual("end-vendor" in str(e), True)
        else:
            self.fail()

    def testEndVendorUnbalanced(self):
        try:
            self.dict.read_dictionary(
                StringIO("VENDOR Simplon 42\nBEGIN-VENDOR Simplon\nEND-VENDOR Oops\n")
            )
        except ParseError as e:
            self.assertEqual("Oops" in str(e), True)
        else:
            self.fail()

    def testEndVendorParsing(self):
        self.dict.read_dictionary(
            StringIO(
                "VENDOR Simplon 42\n"
                "BEGIN-VENDOR Simplon\n"
                "END-VENDOR Simplon\n"
                "ATTRIBUTE Test-Type 1 integer"
            )
        )
        self.assertEqual(self.dict.attrindex["Test-Type"], 1)

    def testInclude(self):
        try:
            self.dict.read_dictionary(
                StringIO(
                    "$INCLUDE this_file_does_not_exist\n"
                    "VENDOR Simplon 42\n"
                    "BEGIN-VENDOR Simplon\n"
                    "END-VENDOR Simplon\n"
                    "ATTRIBUTE Test-Type 1 integer"
                )
            )
        except OSError as e:
            self.assertEqual("this_file_does_not_exist" in str(e), True)
        else:
            self.fail()

    def testDictFilePostParse(self):
        f = DictFile(StringIO("VENDOR Simplon 42\n"))
        for _ in f:
            pass
        self.assertEqual(f.file(), "")
        self.assertEqual(f.line(), -1)

    def testDictFileParseError(self):
        tmpdict = Dictionary()
        try:
            tmpdict.read_dictionary(os.path.join(self.path, "dictfiletest"))
        except ParseError as e:
            self.assertEqual("dictfiletest" in str(e), True)
        else:
            self.fail()


class IncludeSandboxingTests(unittest.TestCase):
    """Regression coverage for the $INCLUDE path-traversal hardening."""

    def test_absolute_include_outside_base_is_rejected(self):
        # $INCLUDE /etc/passwd from an untrusted dictionary used to read
        # whatever the process had access to. Now it must be rejected.
        with self.assertRaisesRegex(ParseError, "escapes the dictionary base"):
            Dictionary(
                StringIO("$INCLUDE /etc/passwd\n"),
                include_base_dir=TEST_ROOT_PATH,
            )

    def test_relative_traversal_is_rejected(self):
        # ../ traversal also escapes the trusted base.
        with self.assertRaisesRegex(ParseError, "escapes the dictionary base"):
            Dictionary(
                StringIO("$INCLUDE ../../../etc/passwd\n"),
                include_base_dir=TEST_ROOT_PATH,
            )

    def test_legitimate_relative_include_still_works(self):
        # Sanity: the canonical FreeRADIUS-style sibling include still
        # resolves under the trusted base.
        d = Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary"))
        self.assertTrue(len(d) > 0)


class VendorIdRangeTests(unittest.TestCase):
    """Regression coverage for the vendor-id range check."""

    def test_negative_vendor_id_is_rejected(self):
        with self.assertRaisesRegex(ParseError, "out of range"):
            Dictionary(StringIO("VENDOR Bogus -1\n"))

    def test_overflow_vendor_id_is_rejected(self):
        # 0x1000000 is one past the 24-bit ceiling.
        with self.assertRaisesRegex(ParseError, "out of range"):
            Dictionary(StringIO("VENDOR Bogus 0x1000000\n"))

    def test_non_integer_vendor_id_is_rejected(self):
        with self.assertRaisesRegex(ParseError, "Invalid vendor id"):
            Dictionary(StringIO("VENDOR Bogus notanumber\n"))

    def test_valid_vendor_id_is_accepted(self):
        d = Dictionary(StringIO("VENDOR Simplon 0xFFFFFF\n"))
        self.assertEqual(d.vendors["Simplon"], 0xFFFFFF)


class ParseErrorMetadataTests(unittest.TestCase):
    """Regression coverage for the ParseError signature tightening (H12)."""

    def test_filename_surfaces_in_error_message(self):
        # Pre-fix this branch passed ``name=state["file"]`` to ParseError,
        # which silently dropped it.
        try:
            Dictionary(
                StringIO("ATTRIBUTE TooFew\n"),
            )
        except ParseError as exc:
            self.assertEqual(exc.file, "")  # StringIO has no filename
            self.assertIn("Incorrect number of tokens", exc.msg or "")
        else:
            self.fail("expected ParseError")

    def test_filename_surfaces_for_file_input(self):
        # The same error from a real file must carry the file name.
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".dict", delete=False) as f:
            f.write("ATTRIBUTE TooFew\n")
            fname = f.name
        try:
            try:
                Dictionary(fname)
            except ParseError as exc:
                self.assertEqual(os.path.basename(fname), exc.file)
                self.assertIn(os.path.basename(fname), str(exc))
            else:
                self.fail("expected ParseError")
        finally:
            os.unlink(fname)

    def test_unknown_kwargs_are_rejected(self):
        # The old **data signature silently swallowed name=. The tightened
        # signature must reject it so future drift is impossible.
        with self.assertRaises(TypeError):
            ParseError("oops", name="ignored")  # type: ignore[call-arg]
