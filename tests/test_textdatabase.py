"""Tests for ``server.database.TextDatabase``.

These tests are integration-shaped — they hit the real filesystem via
``tmp_path`` rather than mocking ``open``, because the file format
(tab-separated, line-per-account) is part of the contract we're
testing. Mocks would let drift hide.

Each test gets its own temp accounts file. The DB instance is real;
we just rebind ``self.accountsFile`` after construction so we don't
have to monkeypatch ``DB_FILE_ACCOUNTS`` from ``config``.
"""
from __future__ import annotations

import pytest

from server.database.TextDatabase import TextDatabase
from shared.HLTypes import HLAccount


@pytest.fixture
def db(tmp_path):
    """Fresh TextDatabase pointed at a temp accounts file. The file is
    not pre-created — empty-DB tests must work before the first save.
    """
    instance = TextDatabase()
    instance.accountsFile = str(tmp_path / "accounts.txt")
    return instance


@pytest.fixture
def admin_account():
    a = HLAccount(login="admin")
    a.password = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5("password")
    a.name = "Administrator"
    a.privs = 0xFFFFFFFFFFFFFFFF
    a.fileRoot = ""
    return a


@pytest.fixture
def guest_account():
    a = HLAccount(login="guest")
    a.password = ""  # no-password account, like the default phxd guest
    a.name = "Guest"
    a.privs = 0
    a.fileRoot = ""
    return a


# ---------------------------------------------------------------------------
# loadAccount
# ---------------------------------------------------------------------------


class TestLoadAccount:
    def test_returns_none_when_file_missing(self, db):
        assert db.loadAccount("admin") is None

    def test_returns_none_for_unknown_login(self, db, admin_account):
        db.saveAccount(admin_account)
        assert db.loadAccount("ghost") is None

    def test_round_trips_all_fields(self, db, admin_account):
        db.saveAccount(admin_account)
        loaded = db.loadAccount("admin")
        assert loaded is not None
        assert loaded.login == admin_account.login
        assert loaded.password == admin_account.password
        assert loaded.name == admin_account.name
        assert loaded.privs == admin_account.privs

    def test_accepts_bytes_login(self, db, admin_account):
        # Wire-side code paths sometimes hand TextDatabase ``bytes`` (the
        # ``_as_str`` helper exists exactly for this). The lookup must
        # still match.
        db.saveAccount(admin_account)
        loaded = db.loadAccount(b"admin")
        assert loaded is not None
        assert loaded.login == "admin"


# ---------------------------------------------------------------------------
# saveAccount — create vs update
# ---------------------------------------------------------------------------


class TestSaveAccount:
    def test_creates_new_account_when_id_zero(self, db, admin_account):
        # Fresh ``HLAccount`` defaults to id=0. saveAccount should treat
        # that as "insert", not "update", so the row appears in the file.
        assert admin_account.id == 0
        result = db.saveAccount(admin_account)
        assert result is True
        assert db.loadAccount("admin") is not None

    def test_assigns_next_uid_to_new_accounts(self, db, admin_account, guest_account):
        # Two creates against a fresh DB should produce id=1 and id=2 —
        # the regression we previously fixed (Py3 string-vs-int compare)
        # used to crash on the second save.
        db.saveAccount(admin_account)
        db.saveAccount(guest_account)
        a = db.loadAccount("admin")
        g = db.loadAccount("guest")
        assert a.id == 1
        assert g.id == 2

    def test_rejects_duplicate_login_on_create(self, db, admin_account):
        db.saveAccount(admin_account)
        # Creating a second admin (id=0) with the same login must fail.
        dup = HLAccount(login="admin")
        dup.password = "different"
        dup.name = "Imposter"
        assert db.saveAccount(dup) is False
        # Original still loadable, unchanged.
        loaded = db.loadAccount("admin")
        assert loaded.name == "Administrator"

    def test_updates_existing_when_id_nonzero(self, db, admin_account):
        db.saveAccount(admin_account)
        loaded = db.loadAccount("admin")
        loaded.name = "Updated Name"
        loaded.privs = 0xABCD
        assert db.saveAccount(loaded) is True
        reloaded = db.loadAccount("admin")
        assert reloaded.name == "Updated Name"
        assert reloaded.privs == 0xABCD


# ---------------------------------------------------------------------------
# deleteAccount
# ---------------------------------------------------------------------------


class TestDeleteAccount:
    def test_returns_false_when_file_missing(self, db):
        assert db.deleteAccount("admin") is False

    def test_returns_false_for_unknown_login(self, db, admin_account):
        db.saveAccount(admin_account)
        assert db.deleteAccount("ghost") is False
        assert db.loadAccount("admin") is not None

    def test_removes_account(self, db, admin_account):
        db.saveAccount(admin_account)
        assert db.deleteAccount("admin") is True
        assert db.loadAccount("admin") is None

    def test_accepts_bytes_login(self, db, admin_account):
        db.saveAccount(admin_account)
        assert db.deleteAccount(b"admin") is True


# ---------------------------------------------------------------------------
# listAccounts — newly added for the Administer Accounts window
# ---------------------------------------------------------------------------


class TestListAccounts:
    def test_returns_empty_list_when_file_missing(self, db):
        # Critical contract: handleAccountList iterates the result, so a
        # missing file must not raise.
        assert db.listAccounts() == []

    def test_returns_all_accounts(self, db, admin_account, guest_account):
        db.saveAccount(admin_account)
        db.saveAccount(guest_account)
        listed = db.listAccounts()
        assert len(listed) == 2
        logins = {a.login for a in listed}
        assert logins == {"admin", "guest"}

    def test_preserves_account_data(self, db, admin_account):
        db.saveAccount(admin_account)
        (loaded,) = db.listAccounts()
        assert loaded.password == admin_account.password
        assert loaded.name == admin_account.name
        assert loaded.privs == admin_account.privs

    def test_skips_malformed_rows(self, db, admin_account, tmp_path):
        # Real-world DB files sometimes pick up partially-written rows
        # (process killed mid-save, etc). The admin window must not be
        # locked out by a single bad line.
        db.saveAccount(admin_account)
        with open(db.accountsFile, "a") as fp:
            fp.write("garbage_row_with_no_tabs\n")
            fp.write("not\tenough\tcolumns\n")
        listed = db.listAccounts()
        # Only the well-formed admin row survives the skip-malformed filter.
        assert len(listed) == 1
        assert listed[0].login == "admin"

    def test_independent_from_loadAccount(self, db, admin_account):
        # ``listAccounts`` must not mutate state ``loadAccount`` reads
        # from — accidental in-place edits in the iteration code would
        # break the Administer Accounts window's "click to edit" flow.
        db.saveAccount(admin_account)
        db.listAccounts()
        loaded = db.loadAccount("admin")
        assert loaded is not None
