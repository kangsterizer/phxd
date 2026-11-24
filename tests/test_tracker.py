"""Tests for tracker registration (``server.HLTracker`` and
``HLServer.updateTrackers``).

Regressions covered:

* Under Python 3 ``buildTrackerClientPacket`` raised ``TypeError`` because
  the server name/description are ``str`` but the packet is built with a
  ``bytes`` format string, so every tracker update failed.
* A tracker whose hostname no longer resolves leaked one UDP socket per
  refresh period. Once the ephemeral port range was exhausted
  ``listenUDP`` raised, and because the ``LoopingCall`` had no errback,
  tracker updates stopped for good.
"""
from __future__ import annotations

import struct

import pytest

from shared.HLProtocol import buildTrackerClientPacket


class FakeUDPTransport:
    def __init__(self, fail_on_write=False):
        self.closed = False
        self.connected_to = None
        self.written = []
        self.fail_on_write = fail_on_write

    def connect(self, host, port):
        self.connected_to = (host, port)

    def write(self, data):
        if self.fail_on_write:
            raise OSError("boom")
        self.written.append(data)

    def loseConnection(self):
        self.closed = True


class FakeTrackerServer:
    def __init__(self, users=3):
        self.users = users
        self.events = []

    def getUserCount(self):
        return self.users

    def logEvent(self, log_type, message, user=None):
        self.events.append((log_type, message))


class FakeFailure:
    def getErrorMessage(self):
        return "DNS lookup failed"


def parse_tracker_packet(data):
    """Splits a tracker registration packet into its fields."""
    assert data[:2] == b"\x00\x01"
    port, users, tls_port = struct.unpack(">HHH", data[2:8])
    pos = 12  # skip the random 4-byte id
    name_len = data[pos]
    name = data[pos + 1 : pos + 1 + name_len]
    pos += 1 + name_len
    desc_len = data[pos]
    desc = data[pos + 1 : pos + 1 + desc_len]
    pos += 1 + desc_len
    assert data[pos:] == b"\x00"
    return port, users, name, desc, tls_port


class TestBuildTrackerClientPacket:
    def test_accepts_str_name_and_description(self):
        data = buildTrackerClientPacket("Chatonly.org", "Since 1998", 5500, 2)
        assert parse_tracker_packet(data) == (5500, 2, b"Chatonly.org", b"Since 1998", 0)

    def test_advertises_tls_port(self):
        data = buildTrackerClientPacket("srv", "desc", 5500, 3, 5600)
        assert parse_tracker_packet(data) == (5500, 3, b"srv", b"desc", 5600)

    def test_accepts_bytes(self):
        data = buildTrackerClientPacket(b"srv", b"desc", 5500, 0)
        assert parse_tracker_packet(data)[2:4] == (b"srv", b"desc")

    def test_encodes_as_mac_roman(self):
        data = buildTrackerClientPacket("Café", "", 5500, 0)
        assert parse_tracker_packet(data)[2] == "Café".encode("mac-roman")

    def test_long_strings_are_truncated_to_255_bytes(self):
        data = buildTrackerClientPacket("n" * 300, "d" * 200, 5500, 0)
        _, _, name, desc, _ = parse_tracker_packet(data)
        assert len(name) == 255
        assert len(desc) == 200


class TestHLTrackerClient:
    def _client(self, transport, server=None):
        from server.HLTracker import HLTrackerClient

        client = HLTrackerClient(server or FakeTrackerServer(), "tracker.example", 5499)
        client.transport = transport
        return client

    def test_update_sends_packet_and_closes_socket(self):
        transport = FakeUDPTransport()
        self._client(transport).update("192.0.2.1")
        assert transport.connected_to == ("192.0.2.1", 5499)
        assert len(transport.written) == 1
        assert transport.closed

    def test_update_advertises_configured_tls_port(self, monkeypatch):
        import server.HLTracker as tracker

        monkeypatch.setattr(tracker, "HOTLINE_TLS_PORT", 5600)
        transport = FakeUDPTransport()
        self._client(transport).update("192.0.2.1")
        assert parse_tracker_packet(transport.written[0])[4] == 5600

    def test_update_closes_socket_when_sending_fails(self):
        transport = FakeUDPTransport(fail_on_write=True)
        server = FakeTrackerServer()
        self._client(transport, server).update("192.0.2.1")
        assert transport.closed
        assert any("Failed to update tracker" in msg for _, msg in server.events)

    def test_dns_failure_closes_socket(self):
        transport = FakeUDPTransport()
        server = FakeTrackerServer()
        self._client(transport, server).resolutionFailed(FakeFailure())
        assert transport.closed
        assert any("DNS lookup failed" in msg for _, msg in server.events)


class TestUpdateTrackers:
    def test_one_failing_tracker_does_not_stop_the_others(self, monkeypatch):
        import server.HLServer as hlserver

        monkeypatch.setattr(
            hlserver, "TRACKER_LIST", [("bad.example", 5499), ("good.example", 5499)]
        )
        started = []

        def fake_listen_udp(port, protocol):
            if protocol.hostname == "bad.example":
                raise OSError("Address in use")
            started.append(protocol.hostname)

        monkeypatch.setattr(hlserver.reactor, "listenUDP", fake_listen_udp)
        server = FakeTrackerServer()
        # Must not raise: an exception here would kill the LoopingCall.
        hlserver.HLServer.updateTrackers(server)
        assert started == ["good.example"]
        assert any("bad.example" in msg for _, msg in server.events)
