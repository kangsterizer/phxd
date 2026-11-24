"""End-to-end tests for Hotline over TLS, including file transfers.

The client side is a pyOpenSSL connection driven in memory against phxd's
own TLS stack (``TLSMemoryBIOFactory``, which ``reactor.listenSSL`` uses),
for both the main Hotline connection and the file transfer connection, as
the mierau/hotline client does with its "secure connection" (TLS port 5600,
transfers on 5601).
"""
from __future__ import annotations

import os
import struct

import pytest
from OpenSSL import SSL
from twisted.internet.address import IPv4Address
from twisted.internet.error import ConnectionDone
from twisted.internet.testing import StringTransport
from twisted.protocols.tls import TLSMemoryBIOFactory
from twisted.python.failure import Failure

from server.HLTLS import ReloadingTLSContextFactory
from shared.HLProtocol import (
    DATA_FILENAME,
    DATA_ICON,
    DATA_LOGIN,
    DATA_NICK,
    DATA_PASSWORD,
    DATA_XFERID,
    DATA_XFERSIZE,
    HLEncode,
    HLObject,
    HTLC_HDR_FILE_GET,
    HTLC_HDR_FILE_LIST,
    HTLC_HDR_FILE_PUT,
    HTLC_HDR_LOGIN,
    HTLS_HDR_TASK,
    PRIV_DOWNLOAD_FILES,
    PRIV_UPLOAD_ANYWHERE,
    PRIV_UPLOAD_FILES,
)
from tests.irc_harness import irc_server  # noqa: F401  (fixture)
from tests.test_tls import write_cert


class InMemoryTLSClient:
    """A TLS client connected to one of phxd's factories through
    ``TLSMemoryBIOFactory``, pumped by hand on the harness clock."""

    def __init__(self, clock, wrapped_factory, context_factory, port):
        self.clock = clock
        address = IPv4Address("TCP", "127.0.0.1", port)
        self.protocol = TLSMemoryBIOFactory(context_factory, False, wrapped_factory).buildProtocol(address)
        self.transport = StringTransport(peerAddress=address)
        self.protocol.makeConnection(self.transport)
        self.client = SSL.Connection(SSL.Context(SSL.TLS_CLIENT_METHOD), None)
        self.client.set_connect_state()
        self.received = b""
        self.closed = False
        self.pump()

    def pump(self, rounds=2000):
        """Moves bytes both ways until nothing happens for a while. Twisted's
        TLS transport flushes, and pull producers (file downloads) run, on
        later reactor ticks, so the harness clock is advanced as we go."""
        idle = 0
        for _ in range(rounds):
            progress = False
            try:
                self.client.do_handshake()
            except SSL.WantReadError:
                pass
            try:
                outgoing = self.client.bio_read(1 << 20)
            except SSL.WantReadError:
                outgoing = b""
            if outgoing and not self.closed:
                self.protocol.dataReceived(outgoing)
                progress = True
            self.clock.advance(0.001)
            incoming = self.transport.value()
            self.transport.clear()
            if incoming:
                self.client.bio_write(incoming)
                progress = True
            try:
                while True:
                    chunk = self.client.recv(1 << 20)
                    if not chunk:
                        break
                    self.received += chunk
                    progress = True
            except SSL.WantReadError:
                pass
            except SSL.ZeroReturnError:
                # The server sent close_notify: answer it, as clients do,
                # so the server can finish closing the connection.
                if not self.client.get_shutdown() & SSL.SENT_SHUTDOWN:
                    self.client.shutdown()
                    progress = True
            if self.transport.disconnecting and not self.closed:
                # The server closed the connection: deliver connectionLost
                # like the reactor would.
                self.closed = True
                self.protocol.connectionLost(Failure(ConnectionDone()))
                progress = True
            idle = 0 if progress else idle + 1
            if idle > 20:
                return

    def send(self, data):
        self.client.sendall(data)
        self.pump()


def hotline_packet(packet_type, seq, objects):
    body = struct.pack("!H", len(objects)) + b"".join(
        HLObject(t, d if isinstance(d, bytes) else d.encode("mac-roman")).flatten() for t, d in objects
    )
    return struct.pack("!5L", packet_type, seq, 0, len(body), len(body)) + body


def parse_packets(data):
    """Returns (type, seq, flags, {object type: data}) for each packet."""
    packets, pos = [], 0
    while pos + 20 <= len(data):
        ptype, seq, flags, size, _ = struct.unpack("!5L", data[pos : pos + 20])
        body = data[pos + 20 : pos + 20 + size]
        objects, opos = {}, 2
        for _ in range(struct.unpack("!H", body[:2])[0] if len(body) >= 2 else 0):
            otype, olen = struct.unpack("!2H", body[opos : opos + 4])
            objects[otype] = body[opos + 4 : opos + 4 + olen]
            opos += 4 + olen
        packets.append((ptype, seq, flags, objects))
        pos += 20 + size
    return packets


def reply_to(client, seq):
    replies = [p for p in parse_packets(client.received) if p[0] == HTLS_HDR_TASK and p[1] == seq]
    assert replies, f"no reply to transaction {seq}"
    return replies[-1]


@pytest.fixture
def tls(irc_server, tmp_path):
    cert, key = write_cert(tmp_path, "server", "phxd.test")
    return ReloadingTLSContextFactory(cert, key)


@pytest.fixture
def secure_hotline(irc_server, tls):
    """A Hotline client logged in as ``tester`` over TLS, with file
    transfer privileges."""
    tester = next(a for a in irc_server.database.accounts if a.login == "tester")
    tester.privs |= PRIV_DOWNLOAD_FILES | PRIV_UPLOAD_FILES | PRIV_UPLOAD_ANYWHERE
    client = InMemoryTLSClient(irc_server.clock, irc_server.server, tls, 5600)
    client.send(b"TRTPHOTL" + struct.pack("!2H", 1, 2))
    assert client.received[:8] == b"TRTP\x00\x00\x00\x00"
    client.received = client.received[8:]
    client.send(
        hotline_packet(
            HTLC_HDR_LOGIN,
            1,
            [
                (DATA_LOGIN, HLEncode("tester")),
                (DATA_PASSWORD, HLEncode("s3cret")),
                (DATA_NICK, "secure"),
                (DATA_ICON, struct.pack("!H", 128)),
            ],
        )
    )
    assert reply_to(client, 1)[2] == 0, "login over TLS failed"
    return client


def transfer(irc_server, tls, xfer_id, payload=b"", size=0):
    """Opens a TLS file transfer connection, sends the HTXF header (and an
    upload payload), and returns the client once the transfer is done."""
    client = InMemoryTLSClient(irc_server.clock, irc_server.server.fileserver, tls, 5601)
    client.send(b"HTXF" + struct.pack("!3L", xfer_id, size, 0) + payload)
    return client


def test_login_over_tls(secure_hotline, irc_server):
    assert irc_server.server.getUserCount() >= 1


def test_file_list_over_tls(secure_hotline, irc_server):
    with open(os.path.join("files", "hello.txt"), "wb") as fp:
        fp.write(b"hi")
    secure_hotline.send(hotline_packet(HTLC_HDR_FILE_LIST, 2, []))
    assert reply_to(secure_hotline, 2)[2] == 0
    assert b"hello.txt" in reply_to(secure_hotline, 2)[3].get(0xC8, b"")


def test_download_and_upload_over_tls(secure_hotline, irc_server, tls):
    content = os.urandom(300 * 1024)  # ~19 chunks of 16 KiB
    with open(os.path.join("files", "big.bin"), "wb") as fp:
        fp.write(content)

    # Download.
    secure_hotline.send(hotline_packet(HTLC_HDR_FILE_GET, 2, [(DATA_FILENAME, "big.bin")]))
    _, _, flags, objects = reply_to(secure_hotline, 2)
    assert flags == 0
    xfer_id = struct.unpack("!L", objects[DATA_XFERID])[0]
    xfer_size = struct.unpack("!L", objects[DATA_XFERSIZE])[0]
    download = transfer(irc_server, tls, xfer_id)
    assert len(download.received) == xfer_size
    assert download.received.endswith(content)

    # Upload the same stream back under another name.
    stream = download.received.replace(b"big.bin", b"cpy.bin")
    secure_hotline.send(
        hotline_packet(
            HTLC_HDR_FILE_PUT,
            3,
            [(DATA_FILENAME, "cpy.bin"), (DATA_XFERSIZE, struct.pack("!L", len(stream)))],
        )
    )
    _, _, flags, objects = reply_to(secure_hotline, 3)
    assert flags == 0
    upload = transfer(irc_server, tls, struct.unpack("!L", objects[DATA_XFERID])[0], stream, len(stream))
    assert upload.closed, "server should close the upload connection once complete"
    with open(os.path.join("files", "cpy.bin"), "rb") as fp:
        assert fp.read() == content
