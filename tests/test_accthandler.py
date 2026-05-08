"""Tests for ``server.handlers.AcctHandler``.

Strategy:

* The pure helpers (``_flatten_subfield`` / ``_parse_subfields``) get
  direct unit tests — they're the trickiest part of the new
  tranListUsers / tranUpdateUser plumbing.
* Handler methods are driven against the FakeServer/FakeDatabase
  fakes from ``conftest.py`` plus real HLPacket instances. We assert
  on (a) the database state after dispatch and (b) the packets
  recorded into ``server.sent``.

We don't use any Twisted plumbing here — handlers are pure functions
of ``(server, user, packet)``.
"""
from __future__ import annotations

from struct import pack

import pytest

from server.handlers.AcctHandler import (
    AcctHandler,
    _flatten_subfield,
    _parse_subfields,
)
from shared.HLProtocol import (
    DATA_LOGIN,
    DATA_NICK,
    DATA_PASSWORD,
    DATA_PRIVS,
    DATA_STRING,
    HLEncode,
    HLPacket,
    HTLC_HDR_ACCOUNT_LIST,
    HTLC_HDR_ACCOUNT_UPDATE,
    HTLS_HDR_TASK,
)
from shared.HLTypes import HLException


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestFlattenSubfield:
    """Inner per-account / per-user-op encoder. Mirrors HLObject.flatten
    on the wire but is used inside a DATA_STRING payload, not at the
    transaction-frame level."""

    def test_serialises_bytes_payload(self):
        out = _flatten_subfield(DATA_NICK, b"toiletj")
        # tag(2) + len(2) + data
        assert out == bytes.fromhex("0066") + bytes.fromhex("0007") + b"toiletj"

    def test_encodes_str_as_mac_roman(self):
        out = _flatten_subfield(DATA_NICK, "toiletj")
        assert out == bytes.fromhex("00660007") + b"toiletj"

    def test_handles_empty_payload(self):
        out = _flatten_subfield(DATA_STRING, b"")
        assert out == bytes.fromhex("00650000")


class TestParseSubfields:
    """Inverse of ``_flatten_subfield``. Used to decode the inner blob
    inside each DATA_STRING field of a tranUpdateUser request."""

    def test_decodes_single_field(self):
        # field count = 1, then DATA_NICK / 7 / "toiletj"
        blob = pack("!H", 1) + _flatten_subfield(DATA_NICK, "toiletj")
        parsed = _parse_subfields(blob)
        assert parsed == {DATA_NICK: b"toiletj"}

    def test_decodes_multiple_fields_in_order(self):
        blob = pack("!H", 3)
        blob += _flatten_subfield(DATA_LOGIN, b"admin")
        blob += _flatten_subfield(DATA_NICK, b"Administrator")
        blob += _flatten_subfield(DATA_PRIVS, b"\x00" * 8)
        parsed = _parse_subfields(blob)
        assert parsed[DATA_LOGIN] == b"admin"
        assert parsed[DATA_NICK] == b"Administrator"
        assert parsed[DATA_PRIVS] == b"\x00" * 8

    def test_returns_empty_for_empty_blob(self):
        # Defensive: protocol allows empty sub-packets even if we never
        # produce them. Must not crash.
        assert _parse_subfields(b"") == {}

    def test_returns_empty_for_truncated_header(self):
        assert _parse_subfields(b"\x00") == {}

    def test_stops_cleanly_on_truncated_field(self):
        # Field count says 2, but the second field's body is missing.
        # We accept what we can and bail without raising — handlers
        # downstream will reject the operation if required fields are
        # absent.
        partial = pack("!H", 2) + _flatten_subfield(DATA_NICK, b"ok")
        partial += pack("!HH", DATA_LOGIN, 100)  # claims 100 bytes, none follow
        parsed = _parse_subfields(partial)
        assert DATA_NICK in parsed
        assert DATA_LOGIN not in parsed


# ---------------------------------------------------------------------------
# Wire format helpers
# ---------------------------------------------------------------------------


def _build_account_record(
    *,
    login=None,
    new_login=None,
    name=None,
    password=None,
    privs=None,
):
    """Build the inner sub-packet for a single user op in a
    tranUpdateUser request. Mirrors what the v1.5+ batch editor
    emits (see HTLC_HDR_ACCOUNT_UPDATE in HLProtocol.py)."""
    fields = []
    if login is not None:
        # DATA_STRING (101) — original login on rename / sole field on delete.
        fields.append(_flatten_subfield(DATA_STRING, HLEncode(login)))
    if new_login is not None:
        # DATA_LOGIN (105) — required for create/modify/rename.
        fields.append(_flatten_subfield(DATA_LOGIN, HLEncode(new_login)))
    if name is not None:
        fields.append(_flatten_subfield(DATA_NICK, name))
    if password is not None:
        fields.append(_flatten_subfield(DATA_PASSWORD, password))
    if privs is not None:
        fields.append(_flatten_subfield(DATA_PRIVS, privs))
    body = b"".join(fields)
    return pack("!H", len(fields)) + body


# ---------------------------------------------------------------------------
# Handler registration
# ---------------------------------------------------------------------------


class TestAcctHandlerRegistration:
    def test_registers_all_account_transactions(self):
        from shared.HLProtocol import (
            HTLC_HDR_ACCOUNT_CREATE,
            HTLC_HDR_ACCOUNT_DELETE,
            HTLC_HDR_ACCOUNT_LIST,
            HTLC_HDR_ACCOUNT_MODIFY,
            HTLC_HDR_ACCOUNT_READ,
            HTLC_HDR_ACCOUNT_UPDATE,
        )

        handler = AcctHandler()
        for tx_type in (
            HTLC_HDR_ACCOUNT_READ,
            HTLC_HDR_ACCOUNT_MODIFY,
            HTLC_HDR_ACCOUNT_CREATE,
            HTLC_HDR_ACCOUNT_DELETE,
            HTLC_HDR_ACCOUNT_LIST,
            HTLC_HDR_ACCOUNT_UPDATE,
        ):
            assert tx_type in handler._funcs


# ---------------------------------------------------------------------------
# handleAccountList — tranListUsers (0x015C)
# ---------------------------------------------------------------------------


class TestHandleAccountList:
    def test_admin_gets_full_list(self, fake_server, admin_user, admin_account):
        from tests.conftest import make_account

        fake_server.database.accounts = [
            admin_account,
            make_account(login="guest", name="Guest", privs=0, password=""),
            make_account(login="toiletj", name="Toilet J", privs=0xFF, password="x"),
        ]

        handler = AcctHandler()
        request = HLPacket(HTLC_HDR_ACCOUNT_LIST, seq=42)
        handler.handleAccountList(fake_server, admin_user, request)

        # Exactly one TASK reply, addressed to the admin's uid.
        assert len(fake_server.sent) == 1
        uid, reply = fake_server.sent[0]
        assert uid == admin_user.uid
        assert reply.type == HTLS_HDR_TASK
        assert reply.seq == 42
        # One DATA_STRING per account.
        data_fields = [obj for obj in reply.objs if obj.type == DATA_STRING]
        assert len(data_fields) == 3

    def test_each_account_is_decodable_subpacket(
        self, fake_server, admin_user, admin_account
    ):
        from tests.conftest import make_account

        fake_server.database.accounts = [
            admin_account,
            make_account(login="guest", name="Guest", privs=0, password=""),
        ]

        handler = AcctHandler()
        request = HLPacket(HTLC_HDR_ACCOUNT_LIST, seq=1)
        handler.handleAccountList(fake_server, admin_user, request)

        _, reply = fake_server.sent[0]
        decoded_logins = []
        for obj in reply.objs:
            if obj.type != DATA_STRING:
                continue
            sub = _parse_subfields(obj.data)
            assert DATA_NICK in sub
            assert DATA_LOGIN in sub
            assert DATA_PRIVS in sub
            assert len(sub[DATA_PRIVS]) == 8
            # The login is XOR-encoded on the wire (matches client expectations).
            from shared.HLProtocol import HLDecode

            decoded_logins.append(HLDecode(sub[DATA_LOGIN]).decode("mac-roman"))
        assert sorted(decoded_logins) == ["admin", "guest"]

    def test_password_subfield_only_when_password_set(
        self, fake_server, admin_user, admin_account
    ):
        from tests.conftest import make_account

        fake_server.database.accounts = [
            admin_account,  # password = "x" -> field present
            make_account(login="guest", privs=0, password=""),  # no password -> absent
        ]

        handler = AcctHandler()
        request = HLPacket(HTLC_HDR_ACCOUNT_LIST, seq=1)
        handler.handleAccountList(fake_server, admin_user, request)

        _, reply = fake_server.sent[0]
        from shared.HLProtocol import HLDecode

        for obj in reply.objs:
            if obj.type != DATA_STRING:
                continue
            sub = _parse_subfields(obj.data)
            login = HLDecode(sub[DATA_LOGIN]).decode("mac-roman")
            if login == "admin":
                assert DATA_PASSWORD in sub
                assert sub[DATA_PASSWORD] == b"x"
            elif login == "guest":
                assert DATA_PASSWORD not in sub

    def test_unprivileged_user_raises(self, fake_server, guest_user):
        handler = AcctHandler()
        request = HLPacket(HTLC_HDR_ACCOUNT_LIST, seq=1)
        with pytest.raises(HLException):
            handler.handleAccountList(fake_server, guest_user, request)
        # No reply was queued — the dispatcher converts the exception
        # into an error packet at a higher layer.
        assert fake_server.sent == []


# ---------------------------------------------------------------------------
# handleAccountUpdate — tranUpdateUser (0x015D)
# ---------------------------------------------------------------------------


class TestHandleAccountUpdate:
    def test_creates_new_account_when_login_doesnt_exist(
        self, fake_server, admin_user
    ):
        record = _build_account_record(
            new_login="newbie",
            name="New User",
            password=HLEncode("hunter2"),
            privs=b"\x00" * 8,
        )
        request = HLPacket(HTLC_HDR_ACCOUNT_UPDATE, seq=10)
        request.addBinary(DATA_STRING, record)

        handler = AcctHandler()
        handler.handleAccountUpdate(fake_server, admin_user, request)

        assert fake_server.database.loadAccount("newbie") is not None
        # A single empty TASK ack goes back to the admin.
        assert len(fake_server.sent) == 1
        uid, reply = fake_server.sent[0]
        assert reply.type == HTLS_HDR_TASK
        assert reply.seq == 10
        assert reply.objs == []

    def test_modifies_existing_account_in_place(self, fake_server, admin_user):
        from tests.conftest import make_account

        fake_server.database.accounts.append(
            make_account(login="toiletj", name="Old Name", privs=0xAA, password="x")
        )

        record = _build_account_record(
            new_login="toiletj",
            name="Updated Name",
            # single 0x00 byte = "leave password unchanged" per Mobius semantics
            password=b"\x00",
            privs=b"\x00" * 8,
        )
        request = HLPacket(HTLC_HDR_ACCOUNT_UPDATE, seq=11)
        request.addBinary(DATA_STRING, record)

        handler = AcctHandler()
        handler.handleAccountUpdate(fake_server, admin_user, request)

        updated = fake_server.database.loadAccount("toiletj")
        assert updated.name == "Updated Name"
        # Keep-existing-password sentinel must NOT clear the hash.
        assert updated.password == "x"

    def test_clears_password_when_field_omitted(self, fake_server, admin_user):
        from tests.conftest import make_account

        fake_server.database.accounts.append(
            make_account(
                login="toiletj", name="Old Name", privs=0, password="hashedpw"
            )
        )

        record = _build_account_record(
            new_login="toiletj",
            name="No Password Now",
            # password=None -> not appended to the sub-packet
            privs=b"\x00" * 8,
        )
        request = HLPacket(HTLC_HDR_ACCOUNT_UPDATE, seq=12)
        request.addBinary(DATA_STRING, record)

        handler = AcctHandler()
        handler.handleAccountUpdate(fake_server, admin_user, request)

        updated = fake_server.database.loadAccount("toiletj")
        # Per HTLC_HDR_ACCOUNT_UPDATE semantics: missing password ->
        # store md5 of empty string (effectively no password).
        from hashlib import md5

        assert updated.password == md5(b"").hexdigest()

    def test_delete_when_only_data_string_present(self, fake_server, admin_user):
        from tests.conftest import make_account

        fake_server.database.accounts.append(
            make_account(login="condemned", name="Goodbye", privs=0)
        )

        # Delete record: ONLY DATA_STRING (the XOR'd login) — no DATA_LOGIN
        # or any other sub-field.
        record = pack("!H", 1) + _flatten_subfield(
            DATA_STRING, HLEncode("condemned")
        )
        request = HLPacket(HTLC_HDR_ACCOUNT_UPDATE, seq=13)
        request.addBinary(DATA_STRING, record)

        handler = AcctHandler()
        handler.handleAccountUpdate(fake_server, admin_user, request)

        assert fake_server.database.loadAccount("condemned") is None

    def test_rename_creates_new_login_and_removes_old(
        self, fake_server, admin_user
    ):
        from tests.conftest import make_account

        fake_server.database.accounts.append(
            make_account(login="oldname", name="Same User", privs=0xCC, password="x")
        )

        # Rename: DATA_STRING = old login, DATA_LOGIN = new login.
        # The presence of DATA_STRING with a value distinct from
        # DATA_LOGIN is what triggers the rename branch.
        record = _build_account_record(
            login="oldname",
            new_login="newname",
            name="Same User",
            password=b"\x00",
            privs=b"\x00" * 8,
        )
        request = HLPacket(HTLC_HDR_ACCOUNT_UPDATE, seq=14)
        request.addBinary(DATA_STRING, record)

        handler = AcctHandler()
        handler.handleAccountUpdate(fake_server, admin_user, request)

        assert fake_server.database.loadAccount("oldname") is None
        renamed = fake_server.database.loadAccount("newname")
        assert renamed is not None
        assert renamed.login == "newname"

    def test_empty_request_acks_without_changes(self, fake_server, admin_user):
        # Some clients send empty save batches when the user clicks
        # Save without dirtying anything. We must ack so the UI
        # doesn't hang.
        request = HLPacket(HTLC_HDR_ACCOUNT_UPDATE, seq=15)
        handler = AcctHandler()
        handler.handleAccountUpdate(fake_server, admin_user, request)

        assert len(fake_server.sent) == 1
        _, reply = fake_server.sent[0]
        assert reply.seq == 15
        assert reply.objs == []

    def test_unprivileged_create_raises(self, fake_server, guest_user):
        record = _build_account_record(
            new_login="newbie",
            name="New User",
            password=HLEncode("hunter2"),
            privs=b"\x00" * 8,
        )
        request = HLPacket(HTLC_HDR_ACCOUNT_UPDATE, seq=16)
        request.addBinary(DATA_STRING, record)

        handler = AcctHandler()
        with pytest.raises(HLException):
            handler.handleAccountUpdate(fake_server, guest_user, request)
        assert fake_server.database.loadAccount("newbie") is None

    def test_unprivileged_delete_raises(self, fake_server, guest_user):
        from tests.conftest import make_account

        fake_server.database.accounts.append(
            make_account(login="condemned", privs=0)
        )

        record = pack("!H", 1) + _flatten_subfield(
            DATA_STRING, HLEncode("condemned")
        )
        request = HLPacket(HTLC_HDR_ACCOUNT_UPDATE, seq=17)
        request.addBinary(DATA_STRING, record)

        handler = AcctHandler()
        with pytest.raises(HLException):
            handler.handleAccountUpdate(fake_server, guest_user, request)
        # Account survives the rejected delete.
        assert fake_server.database.loadAccount("condemned") is not None
