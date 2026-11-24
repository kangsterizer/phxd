"""Tests for dead connection detection (TCP keepalive / user timeout)."""
from __future__ import annotations

import socket

import pytest

from server.HLServer import enableDeadPeerDetection, findSocket
from tests.irc_harness import irc_server  # noqa: F401  (fixture)

linux_only = pytest.mark.skipif(
    not all(hasattr(socket, name) for name in ("TCP_KEEPIDLE", "TCP_USER_TIMEOUT")),
    reason="needs Linux TCP socket options",
)


@pytest.fixture
def tcp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    yield sock
    sock.close()


@linux_only
def test_enables_keepalive_and_user_timeout(tcp_socket):
    applied = enableDeadPeerDetection(tcp_socket, idle=60, interval=15, count=4, userTimeout=90)
    get = tcp_socket.getsockopt
    assert get(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
    assert get(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) == 60
    assert get(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL) == 15
    assert get(socket.IPPROTO_TCP, socket.TCP_KEEPCNT) == 4
    assert get(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT) == 90000
    assert applied["TCP_USER_TIMEOUT"] == 90000


@linux_only
def test_uses_config_defaults(tcp_socket):
    enableDeadPeerDetection(tcp_socket)
    assert tcp_socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) == 60
    assert tcp_socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT) == 90000


@linux_only
def test_zero_disables(tcp_socket):
    assert enableDeadPeerDetection(tcp_socket, idle=0, interval=15, count=4, userTimeout=0) == {}
    assert tcp_socket.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 0
    assert tcp_socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT) == 0


class Obj:
    def __init__(self, **attrs):
        self.__dict__.update(attrs)


class TestFindSocket:
    def test_plain_tcp_transport(self, tcp_socket):
        assert findSocket(Obj(socket=tcp_socket)) is tcp_socket

    def test_tls_transport_chain(self, tcp_socket):
        """BufferingTLSTransport -> TLSMemoryBIOProtocol -> tcp.Server."""
        tcp_server = Obj(socket=tcp_socket)
        tls_protocol = Obj(transport=tcp_server)
        buffering = Obj(_protocol=tls_protocol)
        assert findSocket(buffering) is tcp_socket

    def test_tls_protocol_as_transport(self, tcp_socket):
        assert findSocket(Obj(transport=Obj(socket=tcp_socket))) is tcp_socket

    def test_no_socket(self):
        assert findSocket(Obj()) is None
        assert findSocket(None) is None

    def test_real_twisted_tls_layers(self, tcp_socket):
        """The attribute names match Twisted's actual TLS classes."""
        from twisted.protocols.tls import BufferingTLSTransport, TLSMemoryBIOProtocol

        tls_protocol = TLSMemoryBIOProtocol.__new__(TLSMemoryBIOProtocol)
        tls_protocol.transport = Obj(socket=tcp_socket)
        buffering = BufferingTLSTransport.__new__(BufferingTLSTransport)
        buffering._protocol = tls_protocol
        assert findSocket(buffering) is tcp_socket


def test_connections_without_socket_still_work(irc_server):
    """The harness transports have no OS socket; connecting must not fail."""
    client = irc_server.irc_client()
    lines = client.register("alice")
    assert any(" 001 alice " in line for line in lines)



def test_missing_file_root_is_created(irc_server, tmp_path):
    """The harness runs in tmp_path, where FILE_ROOT ("files") didn't exist."""
    import os

    from config import FILE_ROOT

    assert os.path.isdir(tmp_path / FILE_ROOT)


def test_hotline_file_list_on_fresh_server(irc_server):
    from shared.HLProtocol import HTLC_HDR_FILE_LIST, HTLS_HDR_TASK

    hl = irc_server.hotline_client()
    hl.login("guest", "", "hl")
    hl.replies()
    seq = hl.send_packet(HTLC_HDR_FILE_LIST, [])
    assert (HTLS_HDR_TASK, seq, 0) in hl.replies()
