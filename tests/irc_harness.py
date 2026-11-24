"""Integration harness: a real ``HLServer`` with its handlers installed,
driven through fake transports.

Nothing listens on the network: ``listenTCP`` / ``listenUDP`` and the
tracker ``LoopingCall`` are stubbed, and ``reactor.callLater`` is routed
to a ``twisted.internet.task.Clock`` so timers (idle check, IRC auto
guest login) can be advanced deterministically with ``harness.clock``.

Usage::

    def test_something(irc_server):
        client = irc_server.irc_client()
        client.send("NICK alice", "USER alice 0 * :Alice")
        assert any("001 alice" in line for line in client.take())
"""
from __future__ import annotations

import struct
from hashlib import md5

import pytest

from tests.conftest import FakeDatabase, make_account


def md5hex(password: str) -> str:
    return md5(password.encode("mac-roman")).hexdigest()


class HarnessDatabase(FakeDatabase):
    """FakeDatabase plus the bits HLServer itself calls."""

    def checkBanlist(self, addr):
        return None

    def logEvent(self, *args, **kwargs):
        pass


class FakeAddress:
    def __init__(self, host="127.0.0.1", port=40000):
        self.host = host
        self.port = port


class FakeReason:
    def getErrorMessage(self):
        return "connection closed"


class FakeTransport:
    def __init__(self, host="127.0.0.1"):
        self.data = b""
        self.closed = False
        self.protocol = None
        self._peer = FakeAddress(host)

    def write(self, data):
        if self.closed:
            return
        assert isinstance(data, (bytes, bytearray)), "transport.write needs bytes on Python 3"
        self.data += data

    def getPeer(self):
        return self._peer

    def loseConnection(self):
        if self.closed:
            return
        self.closed = True
        if self.protocol is not None:
            self.protocol.connectionLost(FakeReason())


class Client:
    """A connection to the harness server."""

    def __init__(self, server, host="127.0.0.1"):
        self.server = server
        self.transport = FakeTransport(host)
        self.conn = server.buildProtocol(FakeAddress(host))
        self.transport.protocol = self.conn
        self.conn.makeConnection(self.transport)
        self._read = 0

    @property
    def uid(self):
        return self.conn.connID

    @property
    def user(self):
        return self.server.getUser(self.uid)

    @property
    def closed(self):
        return self.transport.closed


class IRCClient(Client):
    def send(self, *lines):
        """Sends the lines in a single write, like a real client would."""
        payload = "".join(line + "\r\n" for line in lines)
        self.conn.dataReceived(payload.encode("mac-roman"))

    def send_raw(self, data: bytes):
        self.conn.dataReceived(data)

    def take(self):
        """Returns the lines received since the last call."""
        new = self.transport.data[self._read :]
        self._read = len(self.transport.data)
        text = new.decode("mac-roman")
        return [line for line in text.replace("\r", "").split("\n") if line]

    def register(self, nick="tester", *extra):
        self.send(f"NICK {nick}", f"USER {nick} 0 * :{nick}", *extra)
        return self.take()


class HotlineClient(Client):
    """Speaks just enough of the Hotline wire protocol for tests."""

    def __init__(self, server, host="127.0.0.1"):
        super().__init__(server, host)
        self.conn.dataReceived(b"TRTPHOTL" + struct.pack("!2H", 1, 2))
        assert self.transport.data[:8] == b"TRTP\x00\x00\x00\x00"
        self._read = 8
        self._seq = 0

    def send_packet(self, packet_type, objects):
        from shared.HLProtocol import HLObject

        self._seq += 1
        body = struct.pack("!H", len(objects)) + b"".join(
            HLObject(t, d if isinstance(d, bytes) else d.encode("mac-roman")).flatten()
            for t, d in objects
        )
        header = struct.pack("!5L", packet_type, self._seq, 0, len(body), len(body))
        self.conn.dataReceived(header + body)
        return self._seq

    def login(self, login="guest", password="", nick="hlclient"):
        from shared.HLProtocol import (
            DATA_ICON,
            DATA_LOGIN,
            DATA_NICK,
            DATA_PASSWORD,
            HLEncode,
            HTLC_HDR_LOGIN,
        )

        return self.send_packet(
            HTLC_HDR_LOGIN,
            [
                (DATA_LOGIN, HLEncode(login)),
                (DATA_PASSWORD, HLEncode(password)),
                (DATA_NICK, nick),
                (DATA_ICON, struct.pack("!H", 128)),
            ],
        )

    def replies(self):
        """Parses the packets received since the last call into
        ``(type, seq, flags)`` tuples."""
        data = self.transport.data[self._read :]
        self._read = len(self.transport.data)
        out = []
        pos = 0
        while pos + 20 <= len(data):
            ptype, seq, flags, size, _ = struct.unpack("!5L", data[pos : pos + 20])
            out.append((ptype, seq, flags))
            pos += 20 + size
        return out


class Harness:
    def __init__(self, server, clock, database):
        self.server = server
        self.clock = clock
        self.database = database

    def irc_client(self, host="127.0.0.1"):
        return IRCClient(self.server, host)

    def hotline_client(self, host="127.0.0.1"):
        return HotlineClient(self.server, host)


DEFAULT_ACCOUNTS = (
    ("guest", "Guest Account", ""),
    ("tester", "Tester", "s3cret"),
)


@pytest.fixture
def irc_server(tmp_path, monkeypatch):
    """A running HLServer (no network) with ``guest`` (no password) and
    ``tester`` / ``s3cret`` accounts."""
    from twisted.internet import reactor, task

    import server.handlers
    import server.HLServer as hlserver
    from shared.HLProtocol import PRIV_READ_CHAT, PRIV_SEND_CHAT, PRIV_USE_ANY_NAME

    # Log files, the text DB and support/exec lookups are all relative to
    # the working directory; keep them out of the repo.
    monkeypatch.chdir(tmp_path)

    clock = task.Clock()
    monkeypatch.setattr(reactor, "callLater", clock.callLater)
    monkeypatch.setattr(reactor, "listenTCP", lambda *args, **kwargs: None)
    monkeypatch.setattr(reactor, "listenUDP", lambda *args, **kwargs: None)
    monkeypatch.setattr(task.LoopingCall, "start", lambda self, *args, **kwargs: None)

    srv = hlserver.HLServer()
    database = HarnessDatabase(
        [
            # Like a typical install, accounts may chat and choose their own nick.
            make_account(
                login=login,
                name=name,
                password=md5hex(password),
                privs=PRIV_USE_ANY_NAME | PRIV_SEND_CHAT | PRIV_READ_CHAT,
            )
            for login, name, password in DEFAULT_ACCOUNTS
        ]
    )
    srv.database = database
    for mod_name in server.handlers.__all__:
        mod = __import__("server.handlers.%s" % mod_name, None, None, "server.handlers")
        mod.installHandler(srv)

    yield Harness(srv, clock, database)

    # HLServer attaches handlers to the process-wide "phxd" logger; drop
    # them so tests don't accumulate handlers (and open files).
    for handler in list(srv.log.handlers):
        srv.log.removeHandler(handler)
        handler.close()
