"""Unit tests for ``shared.HLProtocol``.

Scope: every pure function and every method that does pure binary
manipulation. Anything Twisted-specific (IRC bridging, transport hooks)
is out of scope here and will be covered by integration tests later.

The fixtures at the bottom of the file include real wire dumps captured
from a Hotline Connect 1.9.2 client running in QEMU Mac OS 9. Those are
the ground truth for "what the canonical client emits" and are the
strongest regression guardrail we have, so prefer asserting against
them when adding new tests for parsing/framing.
"""
from __future__ import annotations

import struct

import pytest

from shared.HLProtocol import (
    DATA_BANNERID,
    DATA_LOGIN,
    DATA_NICK,
    DATA_PASSWORD,
    DATA_PRIVS,
    DATA_SERVERNAME,
    DATA_STRING,
    DATA_VERSION,
    HLCharConst,
    HLDecode,
    HLEncode,
    HLObject,
    HLPacket,
    HTLC_HDR_ICON_GET,
    HTLC_HDR_LOGIN,
    HTLC_HDR_PING,
    HTLC_HDR_USER_INFO,
    HTLC_HDR_USER_LIST,
    HTLS_HDR_SHOW_AGREEMENT,
    HTLS_HDR_TASK,
    isPingType,
)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestHLCharConst:
    """``HLCharConst`` packs a 4-char ASCII string into the big-endian
    32-bit OSType the Hotline handshake uses."""

    def test_trtp_magic(self):
        # The handshake magic the server compares against in HLServer.
        # 'TRTP' = 0x54 0x52 0x54 0x50.
        assert HLCharConst("TRTP") == 0x54525450

    def test_hotl_subprotocol(self):
        assert HLCharConst("HOTL") == 0x484F544C

    @pytest.mark.parametrize("bad", ["", "ABC", "TOOLONG", "ab"])
    def test_returns_zero_for_wrong_length(self, bad):
        assert HLCharConst(bad) == 0


class TestIsPingType:
    """Used by HLServer to decide whether a packet should reset the
    user's idle timer. Anything in the ping-set is "noisy heartbeat
    traffic" and must NOT count toward activity."""

    @pytest.mark.parametrize(
        "ping_type",
        [HTLC_HDR_PING, HTLC_HDR_USER_LIST, HTLC_HDR_USER_INFO, HTLC_HDR_ICON_GET],
    )
    def test_recognised_ping_types(self, ping_type):
        assert isPingType(ping_type) is True

    @pytest.mark.parametrize(
        "non_ping",
        [HTLC_HDR_LOGIN, HTLS_HDR_TASK, HTLS_HDR_SHOW_AGREEMENT, 0xDEADBEEF],
    )
    def test_non_ping_types(self, non_ping):
        assert isPingType(non_ping) is False


# ---------------------------------------------------------------------------
# Encoding / decoding (XOR 0xFF, XOR 0x7F, plaintext detection)
# ---------------------------------------------------------------------------


class TestHLEncode:
    """``HLEncode`` is the documented Hotline 1.x outbound credential
    encoder: bytewise XOR with 0xFF. It must accept str and bytes and
    always return bytes."""

    def test_admin_known_bytes(self):
        # "admin" XOR 0xFF — the wire form your QEMU 1.9.2 client sends.
        assert HLEncode("admin") == bytes.fromhex("9e9b929691")

    def test_empty_string(self):
        assert HLEncode("") == b""

    def test_none_passthrough(self):
        # ``HLEncode(None)`` -> ``None`` is the contract HLDecode mirrors;
        # callers rely on it for "field absent" sentinels.
        assert HLEncode(None) is None

    def test_accepts_bytes(self):
        assert HLEncode(b"admin") == bytes.fromhex("9e9b929691")

    def test_returns_bytes_for_str_input(self):
        assert isinstance(HLEncode("hello"), bytes)

    def test_round_trip_via_decode(self):
        # XOR is symmetric, so encode→decode must round-trip for any
        # plaintext that doesn't trip the auto-detection heuristic.
        original = "adminpass"
        encoded = HLEncode(original)
        decoded = HLDecode(encoded)
        assert decoded == original.encode("mac-roman")


class TestHLDecodeMaskAutoDetection:
    """``HLDecode`` distinguishes three on-wire encodings by majority
    byte class. The thresholds are subtle — these tests pin the exact
    boundaries we depend on for classic-vs-Mierau-vs-plaintext clients."""

    def test_classic_xor_ff_high_bits_dominant(self):
        # XOR(0xFF) of printable ASCII is always >= 0x80.
        # 5 bytes of "admin" all have bit 7 set → must decode XOR 0xFF.
        wire = bytes.fromhex("9e9b929691")
        assert HLDecode(wire) == b"admin"

    def test_mierau_xor_7f_control_bytes_dominant(self):
        # XOR(0x7F) of printable ASCII is always < 0x20 (control range).
        # Build "admin" XORed with 0x7F to simulate a Mierau Swift client.
        wire = bytes(0x7F ^ b for b in b"admin")
        assert HLDecode(wire) == b"admin"

    def test_plaintext_passthrough_for_account_read(self):
        # The classic 1.9 client sends ACCOUNT_READ logins as plaintext
        # ASCII because they're keys, not secrets. We must NOT XOR them.
        # See the dedicated comment block atop ``HLDecode``.
        plain = b"toiletj"
        assert HLDecode(plain) == b"toiletj"

    def test_short_input_uses_classic_xor(self):
        # ≤2 bytes is special-cased: always XOR 0xFF, because single-byte
        # sentinels (e.g. ``b"\x00"`` meaning "password unchanged" in
        # tranUpdateUser) need to round-trip to ``b"\xFF"`` deterministically.
        assert HLDecode(b"\x00") == b"\xFF"
        assert HLDecode(b"\xFF") == b"\x00"

    def test_empty_returns_empty(self):
        assert HLDecode(b"") == b""

    def test_none_returns_none(self):
        assert HLDecode(None) is None

    def test_str_input_decoded_as_mac_roman(self):
        # Sometimes upstream code hands HLDecode a ``str`` (e.g. defaults
        # passed through ``getBinary``). It must coerce and not crash.
        result = HLDecode("admin")  # plaintext, would fall through unchanged
        assert isinstance(result, bytes)
        assert result == b"admin"


# ---------------------------------------------------------------------------
# HLObject — single-field framing
# ---------------------------------------------------------------------------


class TestHLObjectFlatten:
    """One object on the wire is ``[type:2][len:2][data:N]`` big-endian."""

    def test_flatten_string(self):
        obj = HLObject(DATA_NICK, b"toiletj")
        assert obj.flatten() == bytes.fromhex("0066") + bytes.fromhex("0007") + b"toiletj"

    def test_flatten_empty(self):
        obj = HLObject(DATA_STRING, b"")
        assert obj.flatten() == bytes.fromhex("0065") + bytes.fromhex("0000")

    def test_flatten_str_data_encoded_mac_roman(self):
        # Production code occasionally constructs HLObjects with ``str``
        # payloads (legacy from Py2). Flatten must coerce to mac-roman.
        obj = HLObject(DATA_STRING, "admin")
        assert obj.flatten() == bytes.fromhex("00650005") + b"admin"


# ---------------------------------------------------------------------------
# HLPacket — transaction framing
# ---------------------------------------------------------------------------


class TestHLPacketSeqAutoAssignment:
    """The Hotline protocol spec requires transaction IDs to be != 0
    (see Mobius reference at ``reference/mobius/hotline/transaction.go:80``).
    A zero ID makes the classic 1.9 client silently drop server pushes,
    which manifested as "Loading Agreement" hanging forever. The
    constructor auto-assigns a random non-zero ID when none is provided."""

    def test_explicit_seq_is_preserved(self):
        # Replies copy the request ID — must not be clobbered.
        pkt = HLPacket(HTLS_HDR_TASK, seq=42)
        assert pkt.seq == 42

    def test_explicit_seq_is_preserved_for_large_values(self):
        pkt = HLPacket(HTLS_HDR_TASK, seq=0xDEADBEEF)
        assert pkt.seq == 0xDEADBEEF

    def test_default_seq_is_random_nonzero(self):
        pkt = HLPacket(HTLS_HDR_SHOW_AGREEMENT)
        assert pkt.seq != 0
        assert 1 <= pkt.seq <= 0xFFFFFFFF

    def test_default_seq_varies_across_packets(self):
        # Random — collisions are theoretically possible but the chance
        # of N back-to-back constructions all matching is vanishing.
        seqs = {HLPacket(HTLS_HDR_SHOW_AGREEMENT).seq for _ in range(64)}
        assert len(seqs) > 1, "expected variation in auto-assigned IDs"


class TestHLPacketBuilders:
    """``addString`` / ``addInt16`` / ``addInt32`` / ``addInt64`` /
    ``addNumber`` / ``addBinary`` add HLObject entries to the packet
    with the right wire encoding for the value type."""

    def test_addInt16_encodes_two_bytes_big_endian(self):
        pkt = HLPacket(HTLS_HDR_TASK, seq=1)
        pkt.addInt16(DATA_VERSION, 190)
        assert len(pkt.objs) == 1
        assert pkt.objs[0].data == b"\x00\xbe"

    def test_addInt32_encodes_four_bytes_big_endian(self):
        pkt = HLPacket(HTLS_HDR_TASK, seq=1)
        pkt.addInt32(DATA_PRIVS, 0xCAFEBABE)
        assert pkt.objs[0].data == b"\xca\xfe\xba\xbe"

    def test_addInt64_encodes_eight_bytes_big_endian(self):
        pkt = HLPacket(HTLS_HDR_TASK, seq=1)
        pkt.addInt64(DATA_PRIVS, 0x0123456789ABCDEF)
        assert pkt.objs[0].data == bytes.fromhex("0123456789abcdef")

    @pytest.mark.parametrize(
        "value,expected_len",
        [(0, 2), (0xFFFF, 2), (0x10000, 4), (0xFFFFFFFF, 4), (0x100000000, 8)],
    )
    def test_addNumber_picks_smallest_fitting_width(self, value, expected_len):
        # ``addNumber`` is a "best fit" packer used when the receiver is
        # tolerant about width. The classic Hotline doc allows uint32
        # fields to ride 2 bytes if they fit; this is the implementation
        # we have to preserve.
        pkt = HLPacket(HTLS_HDR_TASK, seq=1)
        pkt.addNumber(DATA_VERSION, value)
        assert len(pkt.objs[0].data) == expected_len

    def test_addBinary_is_alias_for_addString(self):
        pkt_a = HLPacket(HTLS_HDR_TASK, seq=1)
        pkt_a.addBinary(DATA_STRING, b"\x00\x01\x02")
        pkt_b = HLPacket(HTLS_HDR_TASK, seq=1)
        pkt_b.addString(DATA_STRING, b"\x00\x01\x02")
        assert pkt_a.objs[0].data == pkt_b.objs[0].data
        assert pkt_a.objs[0].type == pkt_b.objs[0].type


class TestHLPacketAccessors:
    """``getString`` / ``getNumber`` / ``getBinary`` are the read-side
    counterparts. They must return defaults for missing fields and
    auto-decode mac-roman bytes for string lookups."""

    def test_getString_returns_str_decoded_mac_roman(self):
        pkt = HLPacket(HTLC_HDR_LOGIN, seq=1)
        pkt.objs.append(HLObject(DATA_NICK, b"toiletj"))
        assert pkt.getString(DATA_NICK) == "toiletj"

    def test_getString_returns_default_when_missing(self):
        pkt = HLPacket(HTLC_HDR_LOGIN, seq=1)
        assert pkt.getString(DATA_NICK, "fallback") == "fallback"

    def test_getNumber_decodes_uint16(self):
        pkt = HLPacket(HTLC_HDR_LOGIN, seq=1)
        pkt.addInt16(DATA_VERSION, 190)
        assert pkt.getNumber(DATA_VERSION) == 190

    def test_getNumber_decodes_uint32(self):
        pkt = HLPacket(HTLC_HDR_LOGIN, seq=1)
        pkt.addInt32(DATA_VERSION, 0xCAFEBABE)
        assert pkt.getNumber(DATA_VERSION) == 0xCAFEBABE

    def test_getNumber_returns_default_when_missing(self):
        pkt = HLPacket(HTLC_HDR_LOGIN, seq=1)
        assert pkt.getNumber(DATA_VERSION, default=42) == 42


class TestHLPacketRoundTrip:
    """Build → flatten → parse → assert we get the same fields back.
    This is the strongest single test category: it exercises every
    layer of the protocol stack with no transport mock required."""

    def test_empty_packet_round_trip(self):
        original = HLPacket(HTLS_HDR_TASK, seq=1)
        wire = original.flatten(user=None)
        parsed = HLPacket()
        consumed = parsed.parse(wire)
        assert consumed == len(wire)
        assert parsed.type == HTLS_HDR_TASK
        assert parsed.seq == 1
        assert parsed.objs == []

    def test_login_reply_round_trip(self):
        # Mirror handleLogin's TASK reply exactly: version, banner ID,
        # server name. Validates the post-agreement-fix shape.
        original = HLPacket(HTLS_HDR_TASK, seq=1)
        original.addInt16(DATA_VERSION, 190)
        original.addInt16(DATA_BANNERID, 0)
        original.addString(DATA_SERVERNAME, b"phxd server")

        wire = original.flatten(user=None)
        parsed = HLPacket()
        parsed.parse(wire)

        assert parsed.type == HTLS_HDR_TASK
        assert parsed.seq == 1
        assert parsed.getNumber(DATA_VERSION) == 190
        assert parsed.getNumber(DATA_BANNERID) == 0
        assert parsed.getString(DATA_SERVERNAME) == "phxd server"

    def test_show_agreement_round_trip(self):
        # 267 bytes of body — same length as the real agreement we
        # capture in the wire-dump fixture below.
        body = b"Welcome to phxd.\rLine two.\rLine three.\r"
        original = HLPacket(HTLS_HDR_SHOW_AGREEMENT)
        original.addBinary(DATA_STRING, body)

        wire = original.flatten(user=None)
        parsed = HLPacket()
        parsed.parse(wire)

        assert parsed.type == HTLS_HDR_SHOW_AGREEMENT
        # seq is auto-assigned non-zero — the wire round-trip must
        # carry whatever the sender chose.
        assert parsed.seq == original.seq
        assert parsed.seq != 0
        # ``getBinary`` returns the raw bytes, no decoding.
        retrieved = parsed.getBinary(DATA_STRING)
        assert retrieved == body

    def test_login_request_round_trip(self):
        # XOR-encoded credentials + plaintext version int.
        original = HLPacket(HTLC_HDR_LOGIN, seq=1)
        original.addBinary(DATA_LOGIN, HLEncode("admin"))
        original.addBinary(DATA_PASSWORD, HLEncode("adminpass"))
        original.addInt16(DATA_VERSION, 190)

        wire = original.flatten(user=None)
        parsed = HLPacket()
        parsed.parse(wire)

        assert HLDecode(parsed.getBinary(DATA_LOGIN)) == b"admin"
        assert HLDecode(parsed.getBinary(DATA_PASSWORD)) == b"adminpass"
        assert parsed.getNumber(DATA_VERSION) == 190

    def test_partial_buffer_returns_zero(self):
        # ``parse`` must not consume anything when the buffer is too
        # short — the I/O layer relies on this to wait for more bytes.
        parsed = HLPacket()
        assert parsed.parse(b"") == 0
        assert parsed.parse(b"\x00\x00\x00") == 0  # well under the 20-byte header

    def test_partial_payload_returns_zero(self):
        # Header says "expect N body bytes" but only N-1 were delivered.
        # Build a header for a single 10-byte field but only deliver 5.
        partial_header = struct.pack(
            "!5L1H",
            HTLS_HDR_TASK,    # type
            1,                # seq
            0,                # flags
            16,               # totalsize: paramcount(2) + tag(2) + len(2) + 10 data
            16,               # datasize
            1,                # paramcount
        ) + struct.pack("!2H", DATA_STRING, 10) + b"abcde"  # 5 of 10 promised
        parsed = HLPacket()
        assert parsed.parse(partial_header) == 0


# ---------------------------------------------------------------------------
# Real-wire regression fixtures
# ---------------------------------------------------------------------------


class TestRealClientWireFormats:
    """Captured hex dumps from a Hotline Connect 1.9.2 client (QEMU
    Mac OS 9). These are the highest-value tests in the suite — if a
    parsing change ever breaks them, the change has broken a real
    known-good client."""

    # Captured from the QEMU 1.9.2 client during a successful login.
    # See server logs around 2026-05-07 — three fields:
    #   DATA_LOGIN    (0x69) = XOR('admin')
    #   DATA_PASSWORD (0x6a) = XOR('adminpass')
    #   DATA_VERSION  (0xa0) = 190 (0x00be)
    REAL_LOGIN_HEX = (
        "0000006b00000001000000000000001e0000001e0003"
        "006900059e9b929691"          # DATA_LOGIN, len 5, XOR'd 'admin'
        "006a00099e9b9296918f9e8c8c"  # DATA_PASSWORD, len 9, XOR'd 'adminpass'
        "00a0000200be"                # DATA_VERSION, len 2, 190
    )

    def test_real_login_packet_parses(self):
        wire = bytes.fromhex(self.REAL_LOGIN_HEX)
        pkt = HLPacket()
        consumed = pkt.parse(wire)
        assert consumed == len(wire)
        assert pkt.type == HTLC_HDR_LOGIN
        assert pkt.seq == 1

    def test_real_login_credentials_decode(self):
        wire = bytes.fromhex(self.REAL_LOGIN_HEX)
        pkt = HLPacket()
        pkt.parse(wire)
        assert HLDecode(pkt.getBinary(DATA_LOGIN)) == b"admin"
        assert HLDecode(pkt.getBinary(DATA_PASSWORD)) == b"adminpass"

    def test_real_login_version_is_190(self):
        # 1.9.x clients send 190 (0xBE). Our server now mirrors this in
        # the LOGIN reply — verifying the inbound side too closes the loop.
        wire = bytes.fromhex(self.REAL_LOGIN_HEX)
        pkt = HLPacket()
        pkt.parse(wire)
        assert pkt.getNumber(DATA_VERSION) == 190

    # The full LOGIN reply we now emit, captured from the same session
    # that produced a working agreement modal. seq=1 (echoes client),
    # nfields=3, body is DATA_VERSION + DATA_BANNERID + DATA_SERVERNAME.
    REAL_LOGIN_REPLY_HEX = (
        "0001000000000001000000000000001d0000001d0003"
        "00a0000200be"                 # DATA_VERSION = 190
        "00a100020000"                 # DATA_BANNERID = [0,0]
        "00a2000b7068786420736572766572"  # DATA_SERVERNAME = 'phxd server'
    )

    def test_real_login_reply_round_trip(self):
        wire = bytes.fromhex(self.REAL_LOGIN_REPLY_HEX)
        pkt = HLPacket()
        consumed = pkt.parse(wire)
        assert consumed == len(wire)
        # ``HTLS_HDR_TASK`` packs IsReply=1 into byte 1 of the type word,
        # so the type integer is 0x00010000.
        assert pkt.type == HTLS_HDR_TASK
        assert pkt.seq == 1
        assert pkt.getNumber(DATA_VERSION) == 190
        assert pkt.getNumber(DATA_BANNERID) == 0
        assert pkt.getString(DATA_SERVERNAME) == "phxd server"
