"""Tests for TLS support (``server.HLTLS`` and ``HLServer.setupTLS``).

Certificates are generated on the fly. The end-to-end test runs a real
TLS handshake between a pyOpenSSL client and phxd's TLS stack (the same
``TLSMemoryBIOFactory`` that ``reactor.listenSSL`` uses), entirely in
memory, then speaks IRC over it.
"""
from __future__ import annotations

import datetime
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from OpenSSL import SSL

from server.HLTLS import ReloadingTLSContextFactory, TLSConfigError, buildServerContext
from tests.conftest import FakeLog
from tests.irc_harness import irc_server  # noqa: F401  (fixture)


def write_cert(directory, name, common_name="phxd.test"):
    """Writes a self-signed certificate and key; returns their paths."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(directory, f"{name}.crt")
    key_path = os.path.join(directory, f"{name}.key")
    with open(cert_path, "wb") as fp:
        fp.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fp:
        fp.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return cert_path, key_path


def replace_file(path, source):
    """Replaces ``path`` with ``source``'s content and bumps its mtime, the
    way a certificate renewal would."""
    with open(source, "rb") as fp:
        data = fp.read()
    with open(path, "wb") as fp:
        fp.write(data)
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))


def served_common_name(context):
    """Handshakes an in-memory client against ``context`` and returns the
    common name of the certificate the server presented."""
    client = SSL.Connection(SSL.Context(SSL.TLS_CLIENT_METHOD), None)
    client.set_connect_state()
    server = SSL.Connection(context, None)
    server.set_accept_state()
    pump_handshake(client, server)
    return common_name(client)


def common_name(connection):
    cert = connection.get_peer_certificate(as_cryptography=True)
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def pump_handshake(client, server):
    for _ in range(20):
        for conn in (client, server):
            try:
                conn.do_handshake()
            except SSL.WantReadError:
                pass
        for src, dst in ((client, server), (server, client)):
            try:
                dst.bio_write(src.bio_read(65536))
            except SSL.WantReadError:
                pass
        if client.get_peer_certificate() is not None and server.get_state_string():
            try:
                client.do_handshake()
                server.do_handshake()
                return
            except SSL.WantReadError:
                continue
    raise AssertionError("TLS handshake did not complete")


class TestBuildServerContext:
    def test_loads_valid_files(self, tmp_path):
        cert, key = write_cert(tmp_path, "a", "first")
        assert served_common_name(buildServerContext(cert, key)) == "first"

    def test_missing_file(self, tmp_path):
        with pytest.raises(TLSConfigError, match="cannot load"):
            buildServerContext(str(tmp_path / "nope.crt"), str(tmp_path / "nope.key"))

    def test_mismatched_key(self, tmp_path):
        cert, _ = write_cert(tmp_path, "a")
        _, other_key = write_cert(tmp_path, "b")
        with pytest.raises(TLSConfigError):
            buildServerContext(cert, other_key)

    def test_rejects_tls_1_1(self, tmp_path):
        cert, key = write_cert(tmp_path, "a")
        old_client_ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        old_client_ctx.set_max_proto_version(SSL.TLS1_1_VERSION)
        client = SSL.Connection(old_client_ctx, None)
        client.set_connect_state()
        server = SSL.Connection(buildServerContext(cert, key), None)
        server.set_accept_state()
        with pytest.raises((SSL.Error, AssertionError)):
            pump_handshake(client, server)


class TestReloadingTLSContextFactory:
    def test_fails_at_startup_without_valid_files(self, tmp_path):
        with pytest.raises(TLSConfigError):
            ReloadingTLSContextFactory(str(tmp_path / "x.crt"), str(tmp_path / "x.key"))

    def test_reuses_context_while_files_unchanged(self, tmp_path):
        cert, key = write_cert(tmp_path, "live", "first")
        factory = ReloadingTLSContextFactory(cert, key)
        assert factory.getContext() is factory.getContext()

    def test_reloads_renewed_certificate(self, tmp_path):
        cert, key = write_cert(tmp_path, "live", "first")
        new_cert, new_key = write_cert(tmp_path, "renewed", "second")
        log = FakeLog()
        factory = ReloadingTLSContextFactory(cert, key, log)
        assert served_common_name(factory.getContext()) == "first"
        replace_file(cert, new_cert)
        replace_file(key, new_key)
        assert served_common_name(factory.getContext()) == "second"
        assert any("Reloaded TLS certificate" in args[0] for _, args in log.records)

    def test_follows_symlinks_like_lets_encrypt(self, tmp_path):
        first = write_cert(tmp_path, "cert1", "first")
        second = write_cert(tmp_path, "cert2", "second")
        live_cert, live_key = tmp_path / "fullchain.pem", tmp_path / "privkey.pem"
        live_cert.symlink_to(first[0])
        live_key.symlink_to(first[1])
        factory = ReloadingTLSContextFactory(str(live_cert), str(live_key))
        assert served_common_name(factory.getContext()) == "first"
        live_cert.unlink()
        live_key.unlink()
        live_cert.symlink_to(second[0])
        live_key.symlink_to(second[1])
        assert served_common_name(factory.getContext()) == "second"

    def test_broken_renewal_keeps_old_certificate_and_logs_once(self, tmp_path):
        cert, key = write_cert(tmp_path, "live", "first")
        log = FakeLog()
        factory = ReloadingTLSContextFactory(cert, key, log)
        with open(cert, "w") as fp:
            fp.write("not a certificate")
        for _ in range(3):
            assert served_common_name(factory.getContext()) == "first"
        errors = [args for level, args in log.records if level == "error"]
        assert len(errors) == 1
        # Once the renewal is completed properly, it is picked up.
        new_cert, new_key = write_cert(tmp_path, "fixed", "second")
        replace_file(cert, new_cert)
        replace_file(key, new_key)
        assert served_common_name(factory.getContext()) == "second"

    def test_missing_files_after_startup_keep_old_certificate(self, tmp_path):
        cert, key = write_cert(tmp_path, "live", "first")
        factory = ReloadingTLSContextFactory(cert, key, FakeLog())
        os.remove(cert)
        assert served_common_name(factory.getContext()) == "first"


class TestSetupTLS:
    @pytest.fixture
    def listen_calls(self, monkeypatch):
        from twisted.internet import reactor

        calls = []
        monkeypatch.setattr(reactor, "listenSSL", lambda *args: calls.append(args))
        return calls

    def test_disabled_when_no_tls_port(self, irc_server, listen_calls):
        assert irc_server.server.setupTLS(0, 0, "", "") is None
        assert listen_calls == []

    def test_requires_cert_and_key(self, irc_server, listen_calls):
        with pytest.raises(SystemExit, match="tls_cert / tls_key are not"):
            irc_server.server.setupTLS(5600, 0, "", "")

    def test_bad_certificate_exits_with_message(self, irc_server, tmp_path, listen_calls):
        with pytest.raises(SystemExit, match="phxd: configuration error: cannot"):
            irc_server.server.setupTLS(0, 6697, str(tmp_path / "x.crt"), str(tmp_path / "x.key"))

    def test_hotline_and_irc_ports_share_one_certificate(self, irc_server, tmp_path, listen_calls):
        cert, key = write_cert(tmp_path, "a")
        server = irc_server.server
        factory = server.setupTLS(5600, 6697, cert, key)
        assert isinstance(factory, ReloadingTLSContextFactory)
        assert sorted(listen_calls, key=lambda c: c[0]) == [
            (5600, server, factory),
            (5601, server.fileserver, factory),
            (6697, server, factory),
        ]

    def test_irc_only(self, irc_server, tmp_path, listen_calls):
        cert, key = write_cert(tmp_path, "a")
        factory = irc_server.server.setupTLS(0, 6697, cert, key)
        assert listen_calls == [(6697, irc_server.server, factory)]

    def test_same_port_for_both_listens_once(self, irc_server, tmp_path, listen_calls):
        cert, key = write_cert(tmp_path, "a")
        server = irc_server.server
        factory = server.setupTLS(5600, 5600, cert, key)
        assert sorted(listen_calls, key=lambda c: c[0]) == [
            (5600, server, factory),
            (5601, server.fileserver, factory),
        ]


def test_irc_login_over_tls_end_to_end(irc_server, tmp_path):
    """A TLS client handshakes with phxd's TLS stack, registers over IRC
    and logs in with NickServ."""
    from twisted.internet.address import IPv4Address
    from twisted.internet.testing import StringTransport
    from twisted.protocols.tls import TLSMemoryBIOFactory

    cert, key = write_cert(tmp_path, "a", "phxd.test")
    context_factory = ReloadingTLSContextFactory(cert, key)
    tls_factory = TLSMemoryBIOFactory(context_factory, False, irc_server.server)
    address = IPv4Address("TCP", "127.0.0.1", 40001)
    protocol = tls_factory.buildProtocol(address)
    transport = StringTransport(peerAddress=address)
    protocol.makeConnection(transport)

    client = SSL.Connection(SSL.Context(SSL.TLS_CLIENT_METHOD), None)
    client.set_connect_state()
    received = b""

    def pump():
        nonlocal received
        for _ in range(20):
            try:
                client.do_handshake()
            except SSL.WantReadError:
                pass
            try:
                outgoing = client.bio_read(65536)
            except SSL.WantReadError:
                outgoing = b""
            if outgoing:
                protocol.dataReceived(outgoing)
            # Twisted's TLS transport batches writes and flushes them on
            # the next reactor tick (callLater(0)), which runs on the
            # harness clock.
            irc_server.clock.advance(0)
            incoming = transport.value()
            transport.clear()
            if incoming:
                client.bio_write(incoming)
            try:
                while True:
                    received += client.recv(65536)
            except (SSL.WantReadError, SSL.ZeroReturnError):
                pass
            if not outgoing and not incoming:
                return

    pump()
    assert common_name(client) == "phxd.test"
    client.sendall(b"CAP LS 302\r\nNICK alice\r\nUSER alice 0 * :Alice\r\nCAP END\r\n")
    pump()
    client.sendall(b"PRIVMSG NickServ :IDENTIFY tester s3cret\r\n")
    pump()

    text = received.decode("mac-roman")
    assert " 001 alice " in text
    assert " 421 " not in text
    assert "You are now identified for tester." in text
    assert "JOIN :#public" in text
