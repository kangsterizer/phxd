# tests

Pytest suite for phxd. Designed to be fast (whole suite under a second
right now) and to grow into three layers:

```
tests/
  test_hlprotocol.py    unit — pure binary protocol manipulation
  test_<handler>.py     unit — handlers driven against fake server/user objects
  integration/          spin up HLServer with a fake transport and exercise flows
  e2e/                  drive a real Hotline client (rusty-hx) against the server
```

## Running

```sh
# install once
pip install -r requirements-dev.txt

# whole suite
pytest

# one file, verbose
pytest -v tests/test_hlprotocol.py

# everything matching a substring
pytest -k "round_trip"

# with coverage
pytest --cov=shared --cov=server --cov-report=term-missing
```

## Philosophy

**Unit tests** for anything that's pure logic — protocol framing, encode/decode
helpers, bit manipulation. These are the cheap, plentiful tests at the bottom
of the pyramid.

**Integration tests** for handlers + the database layer + Twisted plumbing.
Fewer of these; each one should exercise a real flow end to end against
in-memory fakes.

**E2E tests** against an actual Hotline client (rusty-hx), driving a running
server. Reserved for the canonical happy paths — login, agreement, chat,
account admin — because they're expensive to author and slow to run.

## Wire-format fixtures

The most valuable tests in the suite assert against real hex captured from
a Hotline Connect 1.9.2 client running in QEMU Mac OS 9. See
`TestRealClientWireFormats` at the bottom of `test_hlprotocol.py`. When
adding a parser change, add a captured hex case there — it pins behaviour
against ground truth instead of an idealised spec.

When a packet causes the client to misbehave, copy the hex from the server
log (the `writePacket`/`dataReceived` debug lines) into a new fixture
constant before fixing the bug. That way the regression is locked in.
