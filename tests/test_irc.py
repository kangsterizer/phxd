"""Integration tests for the IRC side of phxd, driven through a real
``HLServer`` (see ``tests/irc_harness.py``)."""
from __future__ import annotations

from tests.irc_harness import irc_server  # noqa: F401  (fixture)


def errors(lines):
    """IRC error replies: 421 Unknown command or HL Error notices."""
    return [line for line in lines if " 421 " in line or "HL Error" in line]


def logged_in_irc_client(irc_server, nick="watcher"):
    client = irc_server.irc_client()
    client.register(nick)
    client.send("PRIVMSG loginserv guest")
    client.take()
    assert client.user.isLoggedIn()
    return client


class TestKeepalives:
    def test_pong_is_ignored(self, irc_server):
        client = logged_in_irc_client(irc_server)
        client.send("PONG :phxd", "PONG irc.example.org")
        assert client.take() == []
        assert not client.closed

    def test_pong_does_not_reset_idle_timer(self, irc_server):
        client = logged_in_irc_client(irc_server)
        idle_deadline = client.conn.idleTimer.getTime()
        irc_server.clock.advance(10)
        client.send("PONG :phxd")
        assert client.conn.idleTimer.getTime() == idle_deadline

    def test_ping_is_answered(self, irc_server):
        client = logged_in_irc_client(irc_server)
        client.send("PING :abc")
        assert any(line.startswith("PONG") for line in client.take())

    def test_unknown_command_gets_single_421(self, irc_server):
        client = logged_in_irc_client(irc_server)
        client.send("FOOBAR x")
        lines = client.take()
        assert errors(lines) == [line for line in lines if " 421 " in line]
        assert len(errors(lines)) == 1
        assert "FOOBAR" in errors(lines)[0]
