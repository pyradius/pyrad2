"""Tests for the EAP method registry and ABC.

These are the contract tests for the new ``EapMethod`` protocol and the
``pyrad2.eap.{register_method, get_method}`` lookup the clients use to
pick which method drives a given ``Access-Request``. They run against
the real registry rather than a mock so the EAP-MD5 binding installed
by ``pyrad2.eap.__init__`` is exercised end to end.
"""

import pytest

from pyrad2 import eap
from pyrad2.eap import EapMethod, Md5Method, get_method, register_method


class TestRegistry:
    def test_md5_is_registered_under_the_canonical_name(self):
        # The auth_type string that callers historically set on
        # AuthPacket — must keep resolving to the MD5 method after the
        # package promotion.
        method = get_method("eap-md5")
        assert isinstance(method, Md5Method)

    def test_lookup_returns_a_fresh_instance_each_call(self):
        # Multi-round methods (TLS, MSCHAPv2) need per-conversation
        # state; the registry must hand out a new instance per lookup so
        # two concurrent clients can't see each other's partial state.
        a = get_method("eap-md5")
        b = get_method("eap-md5")
        assert a is not b

    def test_unknown_name_returns_none(self):
        assert get_method("eap-does-not-exist") is None

    def test_none_name_returns_none(self):
        # Convenience: callers can pass AuthPacket.auth_type straight
        # through without an explicit None check.
        assert get_method(None) is None

    def test_register_method_is_idempotent(self):
        # Re-registering the same name replaces the factory cleanly so
        # tests can swap an implementation without polluting later runs.
        class _Stub(EapMethod):
            def start(self, pkt):
                pass

            def respond(self, pkt, challenge):
                pass

        register_method("eap-md5", _Stub)
        try:
            assert isinstance(get_method("eap-md5"), _Stub)
        finally:
            register_method("eap-md5", Md5Method)

        # Restored — the rest of the suite expects the canonical method.
        assert isinstance(get_method("eap-md5"), Md5Method)

    def test_registered_methods_lists_eap_md5(self):
        assert "eap-md5" in eap.registered_methods()


class TestEapMethodAbcContract:
    def test_cannot_instantiate_without_implementing_hooks(self):
        # ``start`` and ``respond`` are abstract — leaving either out
        # must trip Python's abstract-method protection so a faulty
        # method can't silently no-op.
        class _Incomplete(EapMethod):
            pass

        with pytest.raises(TypeError):
            _Incomplete()  # type: ignore[abstract]

    def test_md5_method_satisfies_the_protocol(self):
        # Sanity: instantiation works and both hooks exist as callables.
        method = Md5Method()
        assert callable(method.start)
        assert callable(method.respond)


class TestMd5MethodWiring:
    """The class hooks must dispatch to the byte-level helpers exactly.

    These don't re-test the bytes themselves (that's ``test_eap.py``);
    they prove the class delegates to the long-standing free functions
    so the registry path and the historical direct-call path produce
    the same outputs.
    """

    def test_start_matches_inject_eap_identity(self):
        pkt = {eap.USER_PASSWORD_ATTR: [b"hunter2"]}
        pkt_via_class: dict = {eap.USER_PASSWORD_ATTR: [b"hunter2"]}

        eap.inject_eap_identity(pkt)
        Md5Method().start(pkt_via_class)

        assert pkt[eap.EAP_MESSAGE_ATTR] == pkt_via_class[eap.EAP_MESSAGE_ATTR]

    def test_respond_matches_apply_eap_md5_challenge(self):
        def _make_reply():
            md5_value = b"\x10" + b"\xaa" * 16
            payload = (
                b"\x01\x07"
                + (5 + len(md5_value)).to_bytes(2, "big")
                + b"\x04"
                + md5_value
            )
            return {eap.EAP_MESSAGE_ATTR: [payload], eap.STATE_ATTR: [b"state"]}

        pkt = {eap.USER_PASSWORD_ATTR: [b"pw"]}
        pkt_via_class: dict = {eap.USER_PASSWORD_ATTR: [b"pw"]}

        eap.apply_eap_md5_challenge(pkt, _make_reply())
        Md5Method().respond(pkt_via_class, _make_reply())

        assert pkt[eap.EAP_MESSAGE_ATTR] == pkt_via_class[eap.EAP_MESSAGE_ATTR]
        assert pkt[eap.STATE_ATTR] == pkt_via_class[eap.STATE_ATTR]
