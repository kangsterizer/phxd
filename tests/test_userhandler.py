"""Unit tests for ``server.handlers.UserHandler`` (non-admin paths)."""
from __future__ import annotations

from shared.HLProtocol import (
    DATA_NICK,
    DATA_UID,
    HLPacket,
    HTLC_HDR_USER_CHANGE,
    HTLS_HDR_USER_CHANGE,
    PRIV_USE_ANY_NAME,
)
from shared.HLTypes import HLUser

from tests.conftest import FakeServer, make_account, make_user


class BroadcastingServer(FakeServer):
    def __init__(self, database=None):
        super().__init__(database)
        self.broadcasts = []

    def broadcastPacket(self, packet, priv=0):
        self.broadcasts.append(packet)


def handler():
    from server.handlers.UserHandler import UserHandler

    return UserHandler()


class TestHandleUserChange:
    def test_user_without_account_keeps_nick(self):
        """The idle check dispatches a USER_CHANGE for every connection,
        including ones that haven't logged in yet (no account). That used
        to raise AttributeError on ``user.account.name``."""
        server = BroadcastingServer()
        user = HLUser(uid=7, addr="127.0.0.1")
        user.nick = "lurker"
        assert user.account is None

        handler().handleUserChange(server, user, HLPacket(HTLC_HDR_USER_CHANGE))

        assert user.nick == "lurker"
        assert len(server.broadcasts) == 1
        change = server.broadcasts[0]
        assert change.type == HTLS_HDR_USER_CHANGE
        assert change.getNumber(DATA_UID) == 7

    def test_account_name_forced_without_use_any_name_priv(self):
        server = BroadcastingServer()
        user = make_user(uid=3, account=make_account(login="bob", name="Bob", privs=0))
        packet = HLPacket(HTLC_HDR_USER_CHANGE)
        packet.addString(DATA_NICK, "someone-else")

        handler().handleUserChange(server, user, packet)

        assert user.nick == "Bob"

    def test_requested_nick_kept_with_use_any_name_priv(self):
        server = BroadcastingServer()
        user = make_user(
            uid=3, account=make_account(login="bob", name="Bob", privs=PRIV_USE_ANY_NAME)
        )
        packet = HLPacket(HTLC_HDR_USER_CHANGE)
        packet.addString(DATA_NICK, "Robert")

        handler().handleUserChange(server, user, packet)

        assert user.nick == "Robert"
