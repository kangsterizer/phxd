"""Shared pytest fixtures and path setup for the phxd test suite.

The production code uses repo-root absolute imports (``from shared.HLProtocol
import *``, ``from config import *``). pytest.ini already adds the repo root
to ``sys.path`` via ``pythonpath = .``, so most tests need nothing extra.

This file exists to (a) host fixtures shared across modules and (b) be the
canonical place to add per-suite setup later (e.g. a temp text DB for
integration tests).
"""
from __future__ import annotations

import pathlib
import random
import sys

# Belt-and-braces: even if pytest.ini's ``pythonpath`` directive is absent
# (older pytest, weird invocation), make absolute imports work.
_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import pytest  # noqa: E402  imported here so test modules don't all need to

from shared.HLTypes import HLAccount, HLUser  # noqa: E402


# ---------------------------------------------------------------------------
# Lightweight fakes shared across handler tests
# ---------------------------------------------------------------------------


class FakeLog:
    """Captures log calls so tests can assert on them when relevant.
    Records keep ``(level, args)`` tuples to avoid forcing format-string
    interpolation at test time (the production logger does it lazily)."""

    def __init__(self):
        self.records: list[tuple[str, tuple]] = []

    def _record(self, level):
        def _log(*args, **_kwargs):
            self.records.append((level, args))

        return _log

    def __getattr__(self, name):
        # debug / info / warning / error / exception all behave the same
        # for our purposes — we don't differentiate severities in tests.
        if name in {"debug", "info", "warning", "error", "exception", "critical"}:
            return self._record(name)
        raise AttributeError(name)


class FakeDatabase:
    """In-memory stand-in for HLDatabase. Implements just enough of the
    interface to satisfy the handlers we test. Looks up by login; calls
    return whatever the production interface promises."""

    def __init__(self, accounts=None):
        self.accounts: list[HLAccount] = list(accounts or [])
        # Track stat updates so tests can assert on the "logged in
        # successfully" path without inspecting the wire packet.
        self.stat_updates: list[tuple[str, int, int, bool]] = []

    def loadAccount(self, login):
        if isinstance(login, (bytes, bytearray)):
            login = login.decode("mac-roman")
        for a in self.accounts:
            if a.login == login:
                return a
        return None

    def saveAccount(self, acct):
        for i, existing in enumerate(self.accounts):
            if existing.login == acct.login:
                self.accounts[i] = acct
                return True
        self.accounts.append(acct)
        return True

    def deleteAccount(self, login):
        if isinstance(login, (bytes, bytearray)):
            login = login.decode("mac-roman")
        for i, a in enumerate(self.accounts):
            if a.login == login:
                del self.accounts[i]
                return True
        return False

    def listAccounts(self):
        return list(self.accounts)

    def updateAccountStats(self, login, downloaded, uploaded, setDate=False):
        self.stat_updates.append((login, downloaded, uploaded, setDate))


class FakeServer:
    """Minimal HLServer surface: a database, a logger, and a record of
    sent packets. Handlers under test see exactly what HLServer would
    expose, so flipping a test from "fake server" to "real server with
    fake transport" later won't churn the test code."""

    def __init__(self, database=None):
        self.database = database if database is not None else FakeDatabase()
        self.log = FakeLog()
        self.sent: list[tuple[int, object]] = []
        self.events: list[tuple[int, str, object]] = []

    def sendPacket(self, uid, packet):
        self.sent.append((uid, packet))

    def updateAccounts(self, acct):
        # Production HLServer broadcasts to keep mirror copies in sync.
        # For unit tests we just want the call to be a no-op.
        pass

    def logEvent(self, log_type, message, user=None):
        self.events.append((log_type, message, user))

    def getUser(self, uid):
        # Some handlers look up users by uid; tests that need this
        # should subclass FakeServer and override.
        return None


# ---------------------------------------------------------------------------
# Account / user fixtures
# ---------------------------------------------------------------------------


def make_account(login="admin", name="Administrator", privs=0, password=""):
    """Build an HLAccount with sensible defaults. Use ``privs`` to set
    the bitmask — see HLProtocol's PRIV_* constants. ``password`` is
    expected to already be hashed (md5 hex) in production; tests can
    pass any string sentinel."""
    a = HLAccount(login=login)
    a.id = 0
    a.password = password
    a.name = name
    a.privs = privs
    a.fileRoot = ""
    return a


def make_user(uid=1, account=None):
    """Build a logged-in HLUser. ``hasPriv(p)`` will pass through to
    the underlying account's bitmask."""
    u = HLUser(uid=uid, addr="127.0.0.1")
    u.account = account if account is not None else make_account()
    u.valid = True
    return u


@pytest.fixture
def admin_account():
    """Account with all four user-management privs set. Loads the
    constants from HLProtocol so this fixture stays in sync with any
    future bit reassignments."""
    from shared.HLProtocol import (
        PRIV_CREATE_USERS,
        PRIV_DELETE_USERS,
        PRIV_MODIFY_USERS,
        PRIV_READ_USERS,
    )

    privs = (
        PRIV_CREATE_USERS
        | PRIV_DELETE_USERS
        | PRIV_MODIFY_USERS
        | PRIV_READ_USERS
    )
    return make_account(login="admin", name="Administrator", privs=privs, password="x")


@pytest.fixture
def admin_user(admin_account):
    return make_user(uid=1, account=admin_account)


@pytest.fixture
def guest_user():
    """Logged-in user with zero privs — every admin operation against
    this user must raise HLException."""
    return make_user(uid=2, account=make_account(login="guest", privs=0))


@pytest.fixture
def fake_server():
    return FakeServer()


@pytest.fixture
def fake_db():
    return FakeDatabase()


# ---------------------------------------------------------------------------
# Cross-cutting safety: deterministic RNG per test
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _deterministic_random(request):
    """Seed Python's global ``random`` module to a value derived from
    the test's nodeid before each test runs.

    Why: ``shared.HLProtocol.HLPacket`` calls ``random.randint`` to
    auto-assign transaction IDs, and other code paths may grow similar
    dependencies. Without isolation, a test that seeds the RNG would
    leak that state into every subsequent test on the same xdist worker
    (workers don't garbage-collect or restart between tests), producing
    flakes that depend on test ordering.

    Using a per-test seed keeps each test reproducible while still
    giving each test a distinct random sequence — so probabilistic
    assertions like "64 generated IDs are not all equal" remain
    meaningful, and a flake is still recoverable from its nodeid alone.
    """
    state = random.getstate()
    # ``hash(str)`` is salted per-process by default in Py3.4+; ``zlib.adler32``
    # gives us a stable, fast 32-bit digest that doesn't depend on PYTHONHASHSEED.
    import zlib
    seed = zlib.adler32(request.node.nodeid.encode("utf-8"))
    random.seed(seed)
    try:
        yield
    finally:
        random.setstate(state)
