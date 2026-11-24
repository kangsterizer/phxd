"""Integration tests for the IRC side of phxd, driven through a real
``HLServer`` (see ``tests/irc_harness.py``)."""
from __future__ import annotations

from tests.irc_harness import irc_server, md5hex  # noqa: F401  (fixture)


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


def welcome_index(lines):
    return next(i for i, line in enumerate(lines) if " 001 " in line)


def account_of(client):
    return client.user.account.login if client.user.account else None


class TestRegistration:
    def test_no_421_for_cap_and_user(self, irc_server):
        client = irc_server.irc_client()
        client.send("CAP LS 302", "NICK alice", "USER alice 0 * :Alice", "CAP END")
        assert errors(client.take()) == []

    def test_cap_ls_answered_before_welcome(self, irc_server):
        client = irc_server.irc_client()
        client.send("CAP LS 302", "NICK alice", "USER alice 0 * :Alice")
        lines = client.take()
        cap_replies = [i for i, line in enumerate(lines) if " CAP * LS :" in line]
        assert len(cap_replies) == 1
        assert cap_replies[0] < welcome_index(lines)

    def test_client_waiting_for_cap_reply_before_registering(self, irc_server):
        client = irc_server.irc_client()
        client.send("CAP LS 302")
        assert any(" CAP * LS :" in line for line in client.take())
        assert not client.closed
        client.send("CAP END", "NICK alice", "USER alice 0 * :Alice")
        lines = client.take()
        assert any(" 001 alice " in line for line in lines)
        assert not any(" CAP " in line for line in lines), "CAP LS answered twice"
        assert errors(lines) == []

    def test_cap_req_is_refused(self, irc_server):
        client = irc_server.irc_client()
        client.register("alice")
        client.send("CAP REQ :sasl")
        assert client.take() == [":phxd CAP alice NAK :sasl"]

    def test_waits_for_complete_lines(self, irc_server):
        client = irc_server.irc_client()
        client.send_raw(b"NICK ali")
        assert client.take() == []
        client.send_raw(b"ce\r\nUSER alice 0 * :Alice\r\n")
        assert any(" 001 alice " in line for line in client.take())

    def test_nick_taken_from_nick_line_when_user_comes_first(self, irc_server):
        client = irc_server.irc_client()
        client.send("USER alice 0 * :Alice", "NICK alice")
        assert any(" 001 alice " in line for line in client.take())

    def test_garbage_is_rejected(self, irc_server):
        client = irc_server.irc_client()
        client.send("GET / HTTP/1.0")
        assert any(" 421 " in line for line in client.take())
        assert client.closed


class TestLogin:
    def test_nickserv_identify_account_and_password(self, irc_server):
        client = irc_server.irc_client()
        client.register("bob", "PRIVMSG NickServ :IDENTIFY tester s3cret")
        assert account_of(client) == "tester"

    def test_success_notice(self, irc_server):
        client = irc_server.irc_client()
        client.register("bob")
        client.send("PRIVMSG NickServ :IDENTIFY tester s3cret")
        lines = client.take()
        assert ":NickServ!NickServ@services NOTICE bob :You are now identified for tester." in lines
        assert "NOTICE * :*** You have been forced to join #public" in lines

    def test_nickserv_identify_password_uses_nick_as_account(self, irc_server):
        client = irc_server.irc_client()
        client.register("tester", "PRIVMSG NickServ :IDENTIFY s3cret")
        assert account_of(client) == "tester"

    def test_password_may_contain_spaces(self, irc_server):
        tester = next(a for a in irc_server.database.accounts if a.login == "tester")
        tester.password = md5hex("two words")
        client = irc_server.irc_client()
        client.register("bob", "PRIVMSG NickServ :IDENTIFY tester two words")
        assert account_of(client) == "tester"

    def test_ns_and_nickserv_commands(self, irc_server):
        for command in ("NS IDENTIFY tester s3cret", "NICKSERV IDENTIFY tester s3cret"):
            client = irc_server.irc_client()
            client.register("bob", command)
            assert account_of(client) == "tester", command

    def test_server_password_account_and_password(self, irc_server):
        client = irc_server.irc_client()
        client.send("PASS tester:s3cret", "NICK dave", "USER dave 0 * :Dave")
        assert account_of(client) == "tester"

    def test_server_password_alone_uses_nick_as_account(self, irc_server):
        client = irc_server.irc_client()
        client.send("PASS s3cret", "NICK tester", "USER tester 0 * :T")
        assert account_of(client) == "tester"

    def test_loginserv_still_works(self, irc_server):
        client = irc_server.irc_client()
        client.register("gina", "PRIVMSG loginserv tester s3cret")
        assert account_of(client) == "tester"
        guest = irc_server.irc_client()
        guest.register("gil", "PRIVMSG loginserv guest")
        assert account_of(guest) == "guest"

    def test_wrong_password_is_reported_then_disconnects(self, irc_server):
        client = irc_server.irc_client()
        client.register("eve")
        client.send("PRIVMSG NickServ :IDENTIFY tester nope")
        assert ":NickServ!NickServ@services NOTICE eve :Login failed: Password is incorrect." in client.take()
        assert client.closed

    def test_unknown_account_is_reported(self, irc_server):
        client = irc_server.irc_client()
        client.register("eve")
        client.send("PRIVMSG NickServ :IDENTIFY nobody pw")
        assert any("Login failed: Login is incorrect." in line for line in client.take())

    def test_nickserv_help_shows_usage(self, irc_server):
        client = irc_server.irc_client()
        client.register("fred")
        client.send("PRIVMSG NickServ :HELP")
        assert client.take() == [
            ":NickServ!NickServ@services NOTICE fred :Usage: IDENTIFY <password> or IDENTIFY <account> <password>"
        ]
        assert not client.closed
        assert not client.user.isLoggedIn()

    def test_hotline_login_unaffected(self, irc_server):
        from shared.HLProtocol import HTLS_HDR_TASK

        hl = irc_server.hotline_client()
        seq = hl.login("tester", "s3cret", "hl")
        assert (HTLS_HDR_TASK, seq, 0) in hl.replies()
        bad = irc_server.hotline_client()
        seq = bad.login("tester", "wrong", "hl")
        assert (HTLS_HDR_TASK, seq, 1) in bad.replies()


class TestAutoGuest:
    def test_logged_in_as_guest_after_delay(self, irc_server):
        client = irc_server.irc_client()
        lines = client.register("alice")
        assert any("logged in as guest in 5 seconds" in line for line in lines)
        irc_server.clock.advance(4.9)
        assert not client.user.isLoggedIn()
        irc_server.clock.advance(0.2)
        assert account_of(client) == "guest"
        lines = client.take()
        assert any("JOIN :#public" in line for line in lines)
        assert ":NickServ!NickServ@services NOTICE alice :You are now identified for guest." in lines

    def test_identify_before_delay_wins(self, irc_server):
        client = irc_server.irc_client()
        client.register("bob", "PRIVMSG NickServ :IDENTIFY tester s3cret")
        irc_server.clock.advance(10)
        assert account_of(client) == "tester"
        assert not client.closed

    def test_identify_after_auto_guest_reports_already_logged_in(self, irc_server):
        client = irc_server.irc_client()
        client.register("bob")
        irc_server.clock.advance(6)
        client.take()
        client.send("PRIVMSG NickServ :IDENTIFY tester s3cret")
        assert account_of(client) == "guest"
        assert not client.closed

    def test_no_guest_account(self, irc_server):
        irc_server.database.accounts = [a for a in irc_server.database.accounts if a.login != "guest"]
        client = irc_server.irc_client()
        client.register("alice")
        irc_server.clock.advance(6)
        assert any("No guest account on this server" in line for line in client.take())
        assert not client.closed
        assert not client.user.isLoggedIn()

    def test_guest_login_failure_does_not_disconnect(self, irc_server):
        guest = next(a for a in irc_server.database.accounts if a.login == "guest")
        guest.password = "not-the-md5-of-empty"
        client = irc_server.irc_client()
        client.register("alice")
        irc_server.clock.advance(6)
        assert any("Guest login failed: Password is incorrect." in line for line in client.take())
        assert not client.closed

    def test_disabled_with_zero_delay(self, irc_server, monkeypatch):
        import server.HLServer as hlserver

        monkeypatch.setattr(hlserver, "IRC_GUEST_LOGIN_DELAY", 0)
        client = irc_server.irc_client()
        lines = client.register("alice")
        assert any("/msg loginserv guest" in line for line in lines)
        irc_server.clock.advance(60)
        assert not client.user.isLoggedIn()

    def test_timer_cancelled_on_disconnect(self, irc_server):
        client = irc_server.irc_client()
        client.register("alice")
        assert any(call.func.__name__ == "ircAutoGuest" for call in irc_server.clock.getDelayedCalls())
        client.transport.loseConnection()
        assert not any(call.func.__name__ == "ircAutoGuest" for call in irc_server.clock.getDelayedCalls())
        irc_server.clock.advance(10)  # nothing fires against the closed connection


class TestCaseInsensitiveLogin:
    def test_nick_with_different_case_finds_account(self, irc_server):
        client = irc_server.irc_client()
        lines = client.register("TeStEr", "PRIVMSG NickServ :IDENTIFY s3cret")
        assert account_of(client) == "tester"
        assert any("You are now identified for tester." in line for line in lines)

    def test_server_password_with_different_case(self, irc_server):
        client = irc_server.irc_client()
        client.send("PASS TESTER:s3cret", "NICK x", "USER x 0 * :x")
        assert account_of(client) == "tester"

    def test_ambiguous_accounts_are_refused(self, irc_server):
        from tests.conftest import make_account

        for login in ("dup", "DUP"):
            irc_server.database.accounts.append(
                make_account(login=login, name=login, password=md5hex("pw"))
            )
        client = irc_server.irc_client()
        lines = client.register("Dup", "PRIVMSG NickServ :IDENTIFY pw")
        assert any("Login failed: Login is incorrect." in line for line in lines)
        exact = irc_server.irc_client()
        exact.register("DUP", "PRIVMSG NickServ :IDENTIFY pw")
        assert account_of(exact) == "DUP"

    def test_hotline_logins_stay_case_sensitive(self, irc_server):
        from shared.HLProtocol import HTLS_HDR_TASK

        hl = irc_server.hotline_client()
        seq = hl.login("TESTER", "s3cret", "hl")
        assert (HTLS_HDR_TASK, seq, 1) in hl.replies()


class TestNickConversion:
    def test_safe_nick(self):
        from shared.HLProtocol import ircSafeNick

        assert ircSafeNick("Cat'Killer") == "Cat`Killer"
        assert ircSafeNick("CatKiller") == "CatKiller"
        assert ircSafeNick("BAT McBook Pro") == "BATMcBookPro"
        assert ircSafeNick("café!") == "caf"
        assert ircSafeNick("[x]_y-z^{|}\\`") == "[x]_y-z^{|}\\`"
        assert ircSafeNick("") == ""
        assert ircSafeNick(None) == ""
        assert ircSafeNick(b"Cat'Killer") == "Cat`Killer"

    def _hotline_user_joins(self, irc_server, nick="Cat'Killer"):
        watcher = logged_in_irc_client(irc_server)
        hl = irc_server.hotline_client()
        hl.login("guest", "", nick)
        return watcher, hl

    def test_hotline_user_join_shows_full_nick(self, irc_server):
        watcher, hl = self._hotline_user_joins(irc_server)
        assert f":{hl.uid}_Cat`Killer!~{hl.uid}_Cat`Killer@127.0.0.1 JOIN :#public" in watcher.take()

    def test_hotline_chat_sender_is_valid_nick(self, irc_server):
        from shared.HLProtocol import DATA_STRING, HTLC_HDR_CHAT

        watcher, hl = self._hotline_user_joins(irc_server)
        watcher.take()
        hl.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "hello from hotline")])
        assert ":Cat`Killer PRIVMSG #public :hello from hotline" in watcher.take()

    def test_who_lists_full_nick(self, irc_server):
        watcher, hl = self._hotline_user_joins(irc_server)
        watcher.take()
        watcher.send("WHO #public")
        assert any(f" 352 {hl.uid}_Cat`Killer #public " in line for line in watcher.take())

    def test_nick_change_uses_sanitized_old_nick(self, irc_server):
        from shared.HLProtocol import DATA_NICK, HTLC_HDR_USER_CHANGE

        watcher, hl = self._hotline_user_joins(irc_server)
        watcher.take()
        hl.send_packet(HTLC_HDR_USER_CHANGE, [(DATA_NICK, "Cat'Nap")])
        assert f":{hl.uid}_Cat`Killer NICK {hl.uid}_Cat`Nap" in watcher.take()

    def test_private_chat_join_does_not_crash(self, irc_server):
        from shared.HLProtocol import (
            DATA_CHATID,
            DATA_NICK,
            DATA_UID,
            HLPacket,
            HTLS_HDR_CHAT_USER_CHANGE,
        )

        watcher, hl = self._hotline_user_joins(irc_server)
        packet = HLPacket(HTLS_HDR_CHAT_USER_CHANGE, isIRC=1)
        packet.server = irc_server.server
        packet.addNumber(DATA_CHATID, 3)
        packet.addNumber(DATA_UID, hl.uid)
        packet.addString(DATA_NICK, "Cat'Killer")
        data = packet.flatten(watcher.user)
        assert data == f":{hl.uid}_Cat`Killer!~{hl.uid}_Cat`Killer@127.0.0.1 JOIN :#3\r\n".encode()


class TestKeepaliveReplies:
    def test_irc_pong_echoes_token(self, irc_server):
        client = logged_in_irc_client(irc_server)
        client.send("PING :LAG1732412345", "PING plain-token")
        assert client.take() == [
            "PONG phxd :LAG1732412345",
            "PONG phxd :plain-token",
        ]

    def test_irc_ping_without_token(self, irc_server):
        client = logged_in_irc_client(irc_server)
        client.send("PING")
        assert client.take() == ["PONG phxd :phxd"]

    def test_hotline_keepalive_gets_a_reply(self, irc_server):
        from shared.HLProtocol import HTLC_HDR_PING, HTLS_HDR_PING, HTLS_HDR_TASK

        hl = irc_server.hotline_client()
        hl.login("guest", "", "hl")
        hl.replies()
        seq = hl.send_packet(HTLC_HDR_PING, [])
        replies = hl.replies()
        assert (HTLS_HDR_TASK, seq, 0) in replies
        assert not any(t == HTLS_HDR_PING for t, _, _ in replies)

    def test_irc_ping_before_login_is_answered(self, irc_server):
        client = irc_server.irc_client()
        client.register("early")
        client.send("PING :before-login")
        assert client.take() == ["PONG phxd :before-login"]
