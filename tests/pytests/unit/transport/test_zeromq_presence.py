"""
Tests for subscription-derived minion presence on the zeromq transport.

A publish subscriber announces itself on a dedicated topic nothing is ever
published to, so the master can name the minion behind a connection instead
of inferring it from cached grain IPs, which breaks under NAT (#66295).
The topic is an HMAC of the id under the session key the master issued
at authentication. The bare sha1(minion_id) a minion subscribes to for
delivery under ``zmq_filtering`` is deliberately *not* honoured -- it is
derived from the id alone, so accepting it would let anything able to
reach the publish port both claim presence for a minion and withdraw it
for one really connected. See
``salt.utils.channel.transport_provides_presence``.

These cover the pieces that are easy to get wrong:

- the socket is only an XPUB when something will drain its subscription
  queue -- libzmq buffers those messages indefinitely otherwise,
- a topic resolves only for a minion holding both halves (a session key
  and a currently-accepted key), without re-reading the directory per
  message, and without the rebuild costing what a stranger put in the
  attacker-writable half,
- a topic that does not resolve yet is parked and retried, but not
  forever, and
- the reader turns SUBSCRIBE / UNSUBSCRIBE into presence callbacks and
  stops instead of spinning when its socket goes away.
"""

import ast
import asyncio
import copy
import gc
import hashlib
import logging
import os
import pathlib
import shutil
import stat
import time
import types

import pytest
import zmq
from pytestshellutils.utils import ports

import salt.config
import salt.channel.server as server
import salt.crypt
import salt.payload
import salt.transport.zeromq
import salt.utils.channel
import salt.utils.presence
from tests.support.mock import AsyncMock, MagicMock, patch

log = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.core_test,
]


PREFIX = salt.transport.zeromq.PRESENCE_TOPIC_PREFIX.decode()
_TOPIC_HEX_LEN = salt.transport.zeromq._TOPIC_HEX_LEN


def _strip_prefix(topic):
    """The bare digest, without the announcement prefix."""
    return topic[len(PREFIX) :]


def _hexid(minion_id):
    """The bare delivery topic a ``zmq_filtering`` minion subscribes to.

    Deliberately NOT a presence topic: it is derived from the id alone, so
    accepting it would make presence forgeable by anything that can reach
    the publish port.
    """
    return hashlib.sha1(minion_id.encode()).hexdigest()


@pytest.fixture
def sessions(tmp_path):
    """``<cachedir>/sessions``, where the request server puts session keys."""
    d = tmp_path / "cache" / "sessions"
    d.mkdir(parents=True)
    return d


def _authenticate(sessions, minion_id, pki_dir=None):
    """Stand in for a minion authenticating.

    Gives it both halves of what the master then has: an accepted key
    (it was allowed in) and a session key (it proved who it is). A real
    minion cannot have the second without the first, and presence
    requires both -- the session key names it, the accepted key says it
    is still allowed.

    Write-only on purpose -- reading the key back here would show up in
    tests that count how often the production code reads key files.
    """
    salt.crypt.Crypticle.write_key(str(sessions / minion_id))
    accepted = (
        pki_dir / "minions"
        if pki_dir is not None
        else sessions.parent.parent / "pki" / "minions"
    )
    accepted.mkdir(parents=True, exist_ok=True)
    (accepted / minion_id).write_text("key")


def _assigned(opts, minion_id):
    """The bare topic the master hands this minion at authentication."""
    return salt.utils.presence.topic_for(opts, minion_id)


def _presence_topic(sessions, minion_id):
    """The topic the master assigns this minion.

    Derived from the master's own presence secret, not from anything the
    minion holds -- the minion is handed the result at authentication.
    """
    pki = sessions.parent.parent / "pki"
    return PREFIX + salt.utils.presence.topic_for({"pki_dir": str(pki)}, minion_id)


def _authenticated_but_unseen(sessions, minion_id):
    """A minion the master has accepted but whose key it cannot see yet.

    The topic is assigned from the master's own secret over the accepted
    keys, so "announced before the master could name it" means the
    publish daemon has not yet picked up the accepted key: the rebuild is
    debounced, the directory mtime may lag on a network filesystem, or a
    listing can fail transiently. That is what parking exists for.

    Hides the *accepted* key, which is the only input now. Hiding the
    session key -- which is what this used to do -- no longer withholds
    anything, so the premise would collapse and the test would pass
    without the behaviour it names ever happening.

    Returns ``(topic, reveal)``; call ``reveal()`` to let the master see
    the key.
    """
    _authenticate(sessions, minion_id)
    topic = _presence_topic(sessions, minion_id)
    live = sessions.parent.parent / "pki" / "minions" / minion_id
    hidden = live.parent / f".hidden-{minion_id}"
    live.rename(hidden)

    def reveal():
        hidden.rename(live)

    return topic, reveal


def _unknown_topic(minion_id="nobody"):
    """A correctly shaped topic that no master secret produces.

    Right shape so it is parked and looked up like a real one; wrong
    secret so it never resolves.
    """
    import hmac as _hmac

    return (
        PREFIX
        + _hmac.new(b"never-issued", minion_id.encode(), hashlib.sha256).hexdigest()
    )


@pytest.fixture
def pki_dir(tmp_path):
    accepted = tmp_path / "pki" / "minions"
    accepted.mkdir(parents=True)
    return tmp_path / "pki"


@pytest.fixture
def opts(pki_dir, sessions):
    return {
        "cachedir": str(sessions.parent),
        "pki_dir": str(pki_dir),
        "cluster_id": None,
        "cluster_pki_dir": None,
        "zmq_filtering": True,
        "ipv6": False,
        "pub_hwm": 1000,
        "zmq_backlog": 1000,
        "tcp_keepalive": True,
        "tcp_keepalive_idle": 300,
        "tcp_keepalive_cnt": -1,
        "tcp_keepalive_intvl": -1,
        "zmq_monitor": False,
    }


@pytest.fixture
def pub_server(opts, tmp_path):
    server = salt.transport.zeromq.PublishServer(
        opts,
        pub_path=str(tmp_path / "pub.ipc"),
        pull_path=str(tmp_path / "pull.ipc"),
    )
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def bound_pub_server(opts):
    """A publish server on loopback, for the tests that really bind."""
    server = salt.transport.zeromq.PublishServer(
        opts,
        pub_host="127.0.0.1",
        pub_port=ports.get_unused_localhost_port(),
        pull_host="127.0.0.1",
        pull_port=ports.get_unused_localhost_port(),
    )
    try:
        yield server
    finally:
        server.close()


class FakeFrame(bytes):
    """A frame carrying 0MQ metadata, as ``recv(copy=False)`` returns.

    Plain ``bytes`` has no ``get``, so a socket yielding those would send
    every read down the "no address" path and quietly make the
    ``Peer-Address`` handling untestable.  ``gets`` raises for an absent
    property exactly as pyzmq does, which is the IPC case.
    """

    def __new__(cls, data, address=None, more=False):
        frame = super().__new__(cls, data)
        frame.address = address
        # pyzmq sets this on every frame; the reader uses it to tell a
        # subscription notification from a continuation part of an upstream
        # multipart message.
        frame.more = more
        return frame

    def get(self, name):
        if name != "Peer-Address" or self.address is None:
            raise zmq.error.ZMQError(zmq.EINVAL)
        return self.address


class FakeSubSocket:
    """A stand-in for the XPUB socket that yields canned frames.

    After the canned frames are exhausted ``recv`` raises whatever
    ``final`` holds, which is how each test ends the reader's loop.
    """

    def __init__(self, frames, final=None):
        self.frames = list(frames)
        self.final = final or zmq.error.ZMQError(zmq.ENOTSOCK)
        self.recv_count = 0
        self.copy_args = []

    async def recv(self, copy=True):
        self.recv_count += 1
        self.copy_args.append(copy)
        if self.frames:
            frame = self.frames.pop(0)
            # Plain bytes stand in for a single-part frame, so the tests
            # that predate FakeFrame keep working and still go through the
            # same metadata the reader reads.
            if not isinstance(frame, FakeFrame):
                frame = FakeFrame(frame)
            return frame
        raise self.final

    def close(self):
        """Let PublishServer.close() tear this down like a real socket."""


async def _drain(pub_server, frames, final=None):
    """Run the reader over ``frames`` and return (added, removed) ids."""
    added, removed = [], []

    async def presence_callback(subscriber, msg):
        assert msg is None
        added.append(subscriber.id_)

    def remove_presence_callback(subscriber):
        removed.append(subscriber.id_)

    pub_server.daemon_pub_sock = FakeSubSocket(frames, final=final)
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, remove_presence_callback),
        timeout=10,
    )
    return added, removed


# ---------------------------------------------------------------------------
# Socket type
# ---------------------------------------------------------------------------


def test_pub_socket_is_plain_pub_without_a_subscription_reader(
    bound_pub_server, io_loop
):
    """
    Without a reader the socket must stay a PUB.

    An XPUB queues every subscription message it receives in an unbounded
    internal deque until the application reads it.  Nothing drains it when
    presence is handled elsewhere, so an unconditional XPUB accumulates for
    the life of the master.
    """
    context = zmq.Context()
    try:
        _, pub_sock, monitor = bound_pub_server._get_sockets(
            context, io_loop, subscriptions=False
        )
        assert pub_sock.getsockopt(zmq.TYPE) == zmq.PUB
        monitor.stop()
    finally:
        context.destroy(linger=0)


def test_overlapping_connections_produce_one_presence_edge_each_way(
    bound_pub_server, io_loop
):
    """
    A minion that reconnects before libzmq has reaped its previous connection
    briefly holds two subscriptions to its own identity topic.  That must read
    as one arrival and, once both are gone, one departure -- not as a
    departure the moment the first of them drops.

    libzmq's own per-topic refcounting gives exactly that, which is why
    ``XPUB_VERBOSE`` is deliberately not set: it would add a message per
    duplicate subscribe carrying no new information, and would make the
    socket's pending queue grow with reconnect churn.
    """
    context = zmq.Context()
    subs = []

    def drain(sock, seconds=2):
        out = []
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if sock.poll(100):
                out.append(sock.recv())
        return out

    try:
        _, pub_sock, monitor = bound_pub_server._get_sockets(
            context, io_loop, subscriptions=True
        )
        assert pub_sock.getsockopt(zmq.TYPE) == zmq.XPUB
        for _ in range(2):
            sub = context.socket(zmq.SUB)
            sub.setsockopt(zmq.SUBSCRIBE, b"topic")
            sub.connect(bound_pub_server.pub_uri)
            subs.append(sub)
        assert drain(pub_sock) == [b"\x01topic"]
        subs[0].close()
        assert drain(pub_sock) == []
        subs[1].close()
        assert drain(pub_sock) == [b"\x00topic"]
        monitor.stop()
    finally:
        for sub in subs:
            sub.close()
        context.destroy(linger=0)


# ---------------------------------------------------------------------------
# Topic resolution
# ---------------------------------------------------------------------------


def test_announcement_topic_resolves_against_accepted_keys(
    pub_server, sessions, pki_dir
):
    _authenticate(sessions, "minion-one")
    assert (
        pub_server._topic_to_minion(_presence_topic(sessions, "minion-one"))
        == "minion-one"
    )


def test_unannounced_prefix_is_not_confused_with_an_id(pub_server, sessions, pki_dir):
    _authenticate(sessions, "minion-one")
    assert pub_server._topic_to_minion(PREFIX) is None
    assert pub_server._topic_to_minion(PREFIX + "nonsense") is None


def test_unaccepted_topic_does_not_resolve(pub_server, sessions, pki_dir):
    _authenticate(sessions, "minion-one")
    assert pub_server._topic_to_minion(_unknown_topic("not-a-minion")) is None


def test_dotfiles_are_not_minions(pub_server, sessions, pki_dir):
    """
    A dotted entry in the session directory is a temporary or editor
    file, not a minion, and must be skipped even when it is otherwise a
    perfectly well-formed session key.

    Derived from the *real* key on purpose: a topic built from a bogus
    one fails to resolve whatever the code does, which would make this
    pass without the skip ever running.
    """
    _authenticate(sessions, ".hidden")

    assert pub_server._topic_to_minion(_presence_topic(sessions, ".hidden")) is None


def test_unknown_topics_do_not_rebuild_the_map(pub_server, sessions, pki_dir):
    """
    Subscriptions are unauthenticated remote input: anything that can reach
    the publish port can send them.  Rebuilding the map per unresolved topic
    would let that drive a listdir plus a hash over every accepted key, on
    the ioloop that publishes jobs.
    """
    _authenticate(sessions, "minion-one")
    pub_server._topic_to_minion(_presence_topic(sessions, "minion-one"))

    builds = []
    real_read = pub_server._read_topic_map

    # No parameter: the redesign made this ``_read_topic_map(self)``. A
    # stub with the old signature raises TypeError the instant
    # production calls it, so ``builds`` stays empty and the assertion
    # below cannot fail.
    def counting():
        builds.append(1)
        return real_read()

    pub_server._read_topic_map = counting

    # Past the debounce, so a rebuild is permitted and only the
    # unknown-topic rule can prevent one. Inside it the assertion would
    # hold whatever this test is measuring.
    pub_server._topic_map_min_interval = 0
    for i in range(100):
        assert pub_server._topic_to_minion(_unknown_topic(f"nobody-{i}")) is None
    assert builds == [], (
        f"{len(builds)} rebuilds driven by unresolvable topics -- that is "
        "an unauthenticated peer's lever on the publish loop"
    )


def test_newly_accepted_key_is_picked_up(pub_server, sessions, pki_dir):
    """
    The flip side of not rebuilding per miss: a key accepted while the
    master is running must still resolve, or the minion that just connected
    is invisible until it reconnects.  Accepting a key changes the
    directory's mtime, which is the rebuild trigger.
    """
    # The rebuild debounce is what this test is not about; see
    # test_the_topic_map_rebuild_is_debounced and
    # test_a_subscription_that_did_not_resolve_is_retried for the behaviour
    # that covers the window it introduces.
    pub_server._topic_map_min_interval = 0
    _authenticate(sessions, "minion-one")
    assert pub_server._topic_to_minion(_unknown_topic("minion-two")) is None
    _authenticate(sessions, "minion-two")
    assert (
        pub_server._topic_to_minion(_presence_topic(sessions, "minion-two"))
        == "minion-two"
    )


def test_a_revoked_key_stops_resolving(pub_server, sessions, pki_dir):
    """
    ``salt-key -d`` removes the accepted key. It does *not* remove
    ``<cachedir>/sessions/<minion>`` -- nothing in Salt does -- so a map
    built from session keys alone would go on naming a revoked minion for
    as long as it kept its subscription open, and go on counting it
    against ``max_minions``.

    Deleting the session file instead, as an earlier version of this test
    did, exercises a path no Salt code takes and would pass whether or not
    revocation worked.
    """
    pub_server._topic_map_min_interval = 0
    _authenticate(sessions, "minion-one")
    (pki_dir / "minions" / "minion-one").write_text("key")
    topic = _presence_topic(sessions, "minion-one")
    assert pub_server._topic_to_minion(topic) == "minion-one"

    (pki_dir / "minions" / "minion-one").unlink()

    assert (
        pub_server._topic_to_minion(topic) is None
    ), "a revoked minion is still being named"
    assert (
        sessions / "minion-one"
    ).exists(), "the session file is expected to survive; that is the point"


# ---------------------------------------------------------------------------
# The reader
# ---------------------------------------------------------------------------


async def test_announcement_becomes_presence(pub_server, sessions, pki_dir):
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one").encode()
    added, removed = await _drain(pub_server, [b"\x01" + topic, b"\x00" + topic])
    assert added == ["minion-one"]
    assert removed == ["minion-one"]
    assert pub_server._present == {}


async def test_syndic_is_reported_present(pub_server, sessions, pki_dir):
    """
    A syndic subscribes to ``syndic`` for delivery, which names nobody.  The
    announcement topic is the only identity its publish connection carries,
    and it is why syndics are visible at all.
    """
    _authenticate(sessions, "syndic-one")
    topic = _presence_topic(sessions, "syndic-one").encode()
    added, removed = await _drain(
        pub_server,
        [b"\x01broadcast", b"\x01syndic", b"\x01" + topic, b"\x00" + topic],
    )
    assert added == ["syndic-one"]
    assert removed == ["syndic-one"]


async def test_repeated_subscribe_is_one_present_entry(pub_server, sessions, pki_dir):
    """
    libzmq should not deliver a duplicate subscribe for the same topic, but
    the reader must stay idempotent if one arrives: the same stub has to be
    reused so the final unsubscribe clears it.
    """
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one").encode()
    added, removed = await _drain(
        pub_server, [b"\x01" + topic, b"\x01" + topic, b"\x00" + topic]
    )
    assert added == ["minion-one", "minion-one"]
    assert removed == ["minion-one"]
    assert pub_server._present == {}


async def test_departure_is_honoured_after_the_key_is_deleted(
    pub_server, sessions, pki_dir
):
    """
    Rejecting or deleting a key takes its topic out of the resolution map,
    but the minion holding that topic is still connected and will still
    unsubscribe.  Resolving the topic on the way out would drop that
    unsubscribe and leave the minion reported present for the life of the
    publish daemon.
    """
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one").encode()
    # Without this the map never rebuilds inside the test, the deleted key
    # goes on resolving, and the premise never happens -- the test then
    # passes against a reader that *does* resolve on the way out.
    pub_server._topic_map_min_interval = 0

    added, removed = [], []

    async def presence_callback(subscriber, msg):
        added.append(subscriber.id_)
        # Between the subscribe and the unsubscribe the key goes away.
        (sessions / "minion-one").unlink()
        (pki_dir / "minions" / "minion-one").unlink()

    pub_server.daemon_pub_sock = FakeSubSocket([b"\x01" + topic, b"\x00" + topic])
    await asyncio.wait_for(
        pub_server._subscription_presence(
            presence_callback, lambda subscriber: removed.append(subscriber.id_)
        ),
        timeout=10,
    )
    assert added == ["minion-one"]
    assert removed == ["minion-one"]
    assert pub_server._present == {}


async def test_non_subscription_frames_are_ignored(pub_server, sessions, pki_dir):
    """
    libzmq passes any other message a subscriber sends straight through to
    the application.  Only the two subscription verbs name a presence edge;
    reading the first byte of an arbitrary payload as one would make every
    stray frame look like an arrival.
    """
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one").encode()
    added, removed = await _drain(
        pub_server, [b"\x02" + topic, b"garbage", b"\xff" + topic]
    )
    assert added == []
    assert removed == []
    assert pub_server._present == {}


async def test_unaccepted_topic_is_ignored(pub_server, sessions, pki_dir):
    _authenticate(sessions, "minion-one")
    topic = (PREFIX + "f" * 64).encode()  # right shape, wrong secret
    added, removed = await _drain(pub_server, [b"\x01" + topic, b"\x00" + topic])
    assert added == []
    assert removed == []


async def test_broadcast_and_syndic_topics_are_ignored(pub_server, sessions, pki_dir):
    _authenticate(sessions, "minion-one")
    added, removed = await _drain(
        pub_server,
        [b"\x01broadcast", b"\x01syndic", b"\x00broadcast", b"\x00syndic"],
    )
    assert added == []
    assert removed == []


async def test_non_utf8_topic_is_ignored(pub_server, sessions, pki_dir):
    _authenticate(sessions, "minion-one")
    added, removed = await _drain(pub_server, [b"\x01\xff\xfe\xfd"])
    assert added == []
    assert removed == []


async def test_reader_stops_when_its_socket_goes_away(pub_server):
    """
    close() racing the ioloop leaves recv() raising immediately and
    forever; returning rather than continuing is what keeps that from
    pinning a core and flooding the log.
    """
    added, removed = await _drain(
        pub_server, [], final=zmq.error.ZMQError(zmq.ENOTSOCK)
    )
    assert added == []
    assert pub_server.daemon_pub_sock.recv_count == 1


async def test_reader_gives_up_on_a_persistent_error(pub_server):
    """
    A non-zmq failure may be transient, so the reader retries -- but it must
    not retry forever.  Ten consecutive failures end the interpreting; the
    socket is then drained (and that drain gives up after ten of its own),
    so twenty recvs in total.
    """
    added, removed = await _drain(pub_server, [], final=RuntimeError("boom"))
    assert added == []
    assert pub_server.daemon_pub_sock.recv_count == 20


async def test_reader_survives_a_transient_error(pub_server, sessions, pki_dir):
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one").encode()

    class FlakySocket(FakeSubSocket):
        async def recv(self, copy=True):
            self.recv_count += 1
            if self.recv_count == 1:
                raise RuntimeError("transient")
            return await super().recv(copy=copy)

    added, removed = [], []

    async def presence_callback(subscriber, msg):
        added.append(subscriber.id_)

    pub_server.daemon_pub_sock = FlakySocket([b"\x01" + topic])
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, removed.append),
        timeout=10,
    )
    assert added == ["minion-one"]


async def test_presence_callback_failure_does_not_stop_the_reader(
    pub_server, sessions, pki_dir
):
    _authenticate(sessions, "minion-one")
    _authenticate(sessions, "minion-two")
    seen = []

    async def presence_callback(subscriber, msg):
        if subscriber.id_ == "minion-one":
            raise RuntimeError("event bus is unhappy")
        seen.append(subscriber.id_)

    pub_server.daemon_pub_sock = FakeSubSocket(
        [
            b"\x01" + _presence_topic(sessions, "minion-one").encode(),
            b"\x01" + _presence_topic(sessions, "minion-two").encode(),
        ]
    )
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, None), timeout=10
    )
    assert seen == ["minion-two"]


# ---------------------------------------------------------------------------
# End to end: the subscriber side announces, the publish server reports it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("zmq_filtering", [True, False])
@pytest.mark.parametrize("role", ["minion", "syndic"])
def test_subscriber_announces_itself(opts, sessions, io_loop, zmq_filtering, role):
    """
    Every role announces itself, under both filtering modes.

    The syndic case is the point of the dedicated topic: a syndic subscribes
    to ``syndic`` for delivery, which names nobody, and it cannot subscribe
    to its own sha1(id) instead -- the master publishes jobs to that topic
    for a targeted minion, and a syndic receiving one would forward it to its
    whole sub-tree.
    """
    context = zmq.Context()
    client = None
    try:
        xpub = context.socket(zmq.XPUB)
        port = xpub.bind_to_random_port("tcp://127.0.0.1")

        client_opts = dict(opts, id="sub-one", __role=role, zmq_filtering=zmq_filtering)
        client = salt.transport.zeromq.PublishClient(
            client_opts, io_loop, host="127.0.0.1", port=port
        )
        # The announcement is no longer made at construction: it is derived
        # from the session key, which does not exist until the minion has
        # authenticated. The channel calls this once it has.
        _authenticate(sessions, "sub-one")
        session = salt.crypt.Crypticle.read_key(str(sessions / "sub-one"))
        client.announce_presence(_assigned(opts, "sub-one"))
        client._socket.connect(f"tcp://127.0.0.1:{port}")

        topics = set()
        deadline = time.monotonic() + 30
        want = _presence_topic(sessions, "sub-one").encode()
        while time.monotonic() < deadline:
            if xpub.poll(100):
                frame = xpub.recv()
                if frame[:1] == b"\x01":
                    topics.add(frame[1:])
                if want in topics:
                    break
        assert want in topics
    finally:
        if client is not None:
            client.close()
        context.destroy(linger=0)


def test_announced_topic_resolves_to_the_subscriber(opts, sessions, io_loop, pki_dir):
    """
    Close the loop: what PublishClient puts on the wire is what
    _topic_to_minion resolves back to an id.

    ``zmq_filtering`` is off deliberately. With it on the client also
    subscribes to a bare sha1(id) for delivery -- which this reader
    refuses as identity, but which would still be one more topic to
    account for here and would be a
    test of the delivery topic wearing this one's name.
    """
    _authenticate(sessions, "sub-one")
    context = zmq.Context()
    client = None
    server = salt.transport.zeromq.PublishServer(
        opts,
        pub_host="127.0.0.1",
        pub_port=ports.get_unused_localhost_port(),
        pull_host="127.0.0.1",
        pull_port=ports.get_unused_localhost_port(),
    )
    try:
        xpub = context.socket(zmq.XPUB)
        port = xpub.bind_to_random_port("tcp://127.0.0.1")
        client = salt.transport.zeromq.PublishClient(
            dict(opts, id="sub-one", __role="minion", zmq_filtering=False),
            io_loop,
            host="127.0.0.1",
            port=port,
        )
        _authenticate(sessions, "sub-one")
        session = salt.crypt.Crypticle.read_key(str(sessions / "sub-one"))
        client.announce_presence(_assigned(opts, "sub-one"))
        client._socket.connect(f"tcp://127.0.0.1:{port}")

        announced = set()
        resolved = set()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and "sub-one" not in resolved:
            if xpub.poll(100):
                frame = xpub.recv()
                topic = frame[1:].decode(errors="replace")
                if topic and topic not in ("broadcast", "syndic"):
                    announced.add(topic)
                    minion_id = server._topic_to_minion(topic)
                    if minion_id is not None:
                        resolved.add(minion_id)
        assert resolved == {"sub-one"}
        assert all(
            topic.startswith(salt.transport.zeromq.PRESENCE_TOPIC_PREFIX.decode())
            for topic in announced
        ), f"the id must come from the announcement, not a delivery topic: {announced}"
    finally:
        if client is not None:
            client.close()
        server.close()
        context.destroy(linger=0)


async def test_the_subscriber_stub_carries_the_peer_address(
    pub_server, sessions, pki_dir
):
    """
    ``show_ip=True`` reports this address, so it has to survive the trip
    from the frame into the stub.  The metadata only exists on the frame
    object ``recv(copy=False)`` returns.
    """
    _authenticate(sessions, "sub-one")
    topic = _presence_topic(sessions, "sub-one").encode()
    captured = []

    async def presence_callback(subscriber, msg):
        captured.append((subscriber.id_, subscriber.address))

    pub_server.daemon_pub_sock = FakeSubSocket(
        [FakeFrame(b"\x01" + topic, address="10.0.0.7")]
    )
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )

    assert captured == [("sub-one", "10.0.0.7")]


async def test_a_frame_without_a_peer_address_is_still_a_presence_edge(
    pub_server, sessions, pki_dir
):
    """
    0MQ does not attach ``Peer-Address`` over IPC and raises rather than
    returning nothing.  An address is a nicety; failing to read one must not
    cost the presence event the frame represents.
    """
    _authenticate(sessions, "sub-one")
    topic = _presence_topic(sessions, "sub-one").encode()
    captured = []

    async def presence_callback(subscriber, msg):
        captured.append((subscriber.id_, subscriber.address))

    pub_server.daemon_pub_sock = FakeSubSocket([FakeFrame(b"\x01" + topic)])
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )

    assert captured == [("sub-one", "")]


async def test_subscriptions_are_read_without_copying(pub_server, sessions, pki_dir):
    """
    ``copy=True`` hands back plain bytes and the frame's 0MQ metadata --
    the only place the subscriber's address comes from -- is gone.  Nothing
    else in the reader would notice.
    """
    _authenticate(sessions, "sub-one")

    async def presence_callback(subscriber, msg):
        pass

    sock = FakeSubSocket(
        [FakeFrame(b"\x01" + _presence_topic(sessions, "sub-one").encode())]
    )
    pub_server.daemon_pub_sock = sock
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )

    assert sock.copy_args and not any(sock.copy_args)


async def _await_started(server, timeout=10):
    """``PublishServer.started`` is a multiprocessing Event, so it cannot be
    awaited directly; yield to the loop until the publisher sets it."""
    deadline = time.monotonic() + timeout
    while not server.started.is_set():
        if time.monotonic() > deadline:
            raise AssertionError("publisher never signalled started")
        await asyncio.sleep(0.01)


@pytest.mark.parametrize(
    "presence_opts,expects_reader",
    [
        # The fixture turns zmq_filtering on, so the "no presence" case has
        # to turn it back off explicitly -- otherwise it is not that case.
        ({"transport": "zeromq", "zmq_filtering": False}, False),
        # zmq_filtering is no longer a presence source; only the one
        # option turns it on.
        ({"transport": "zeromq", "zmq_filtering": True}, False),
        (
            {
                "transport": "zeromq",
                "zmq_filtering": False,
                "zmq_presence_subscriptions": True,
            },
            True,
        ),
    ],
)
async def test_publisher_couples_the_socket_type_to_the_reader(
    opts, presence_opts, expects_reader
):
    """
    The socket must be an XPUB exactly when something is draining its
    subscription queue, and the reader must actually be started.

    These are one decision, not two.  An XPUB with no reader buffers every
    subscription message in an unbounded internal deque for the life of the
    master; a reader with no XPUB never sees one, which silently disables
    presence while leaving every other test green.
    """
    server = salt.transport.zeromq.PublishServer(
        dict(opts, **presence_opts),
        pub_host="127.0.0.1",
        pub_port=ports.get_unused_localhost_port(),
        pull_host="127.0.0.1",
        pull_port=ports.get_unused_localhost_port(),
    )
    io_loop = asyncio.get_running_loop()

    async def presence_callback(subscriber, msg):
        pass

    task = io_loop.create_task(
        server.publisher(
            lambda payload: None,
            presence_callback=presence_callback,
            remove_presence_callback=lambda subscriber: None,
            io_loop=io_loop,
        )
    )
    try:
        await _await_started(server)
        expected = zmq.XPUB if expects_reader else zmq.PUB
        assert server.daemon_pub_sock.getsockopt(zmq.TYPE) == expected
        assert (server._presence_task is not None) is expects_reader
    finally:
        task.cancel()
        server.close()


async def test_publisher_starts_no_reader_without_a_presence_callback(opts):
    """
    A transport given nothing to report presence to must not open an XPUB
    whose queue nobody drains.
    """
    server = salt.transport.zeromq.PublishServer(
        dict(
            opts,
            zmq_presence_subscriptions=True,
            zmq_filtering=False,
            transport="zeromq",
        ),
        pub_host="127.0.0.1",
        pub_port=ports.get_unused_localhost_port(),
        pull_host="127.0.0.1",
        pull_port=ports.get_unused_localhost_port(),
    )
    io_loop = asyncio.get_running_loop()
    task = io_loop.create_task(server.publisher(lambda payload: None, io_loop=io_loop))
    try:
        await _await_started(server)
        assert server.daemon_pub_sock.getsockopt(zmq.TYPE) == zmq.PUB
        assert server._presence_task is None
    finally:
        task.cancel()
        server.close()


def test_a_stranger_cannot_inflate_the_rebuild(pub_server, sessions, pki_dir):
    """
    The rebuild runs on the loop that publishes every job and is itself
    triggered by unauthenticated subscriptions, so it has to cost what
    the fleet costs.

    ``ReqServerChannel`` still creates ``<cachedir>/sessions/<id>`` from
    the id in a request, checked for shape and nothing else -- so that
    directory remains attacker-writable. What changed is that the map no
    longer reads it: the accepted keys are the only input, and those an
    outsider cannot create. Planting session files must therefore cost
    the rebuild nothing at all.
    """
    _authenticate(sessions, "minion-one", pki_dir=pki_dir)
    for n in range(5000):
        (sessions / f"stranger-{n}").write_text("x")

    with patch("os.listdir", wraps=os.listdir) as listed:
        topics, complete = pub_server._read_topic_map()

    assert complete
    assert list(topics.values()) == ["minion-one"]
    listed_dirs = [str(c.args[0]) for c in listed.call_args_list]
    assert (
        str(sessions) not in listed_dirs
    ), "the rebuild read the attacker-writable session directory"


async def test_a_stopped_reader_retires_the_channels_record(pub_server, pki_dir):
    """
    The reader reaches the channel through ``presence_callback.__self__``.
    If that wiring breaks -- a transport wrapping the callback, a rename --
    the retirement silently does nothing and the channel goes on
    heartbeating a frozen connected set for the life of the process, which
    is the failure ``stop_recording_presence`` exists to prevent.
    """

    class _Channel:
        def __init__(self):
            self.retired = False

        async def presence_callback(self, subscriber, msg):
            pass

        def stop_recording_presence(self):
            self.retired = True

    channel = _Channel()
    pub_server.daemon_pub_sock = FakeSubSocket([])

    await asyncio.wait_for(
        pub_server._subscription_presence(
            channel.presence_callback, lambda subscriber: None
        ),
        timeout=10,
    )

    assert channel.retired, "the reader stopped without retiring the record"


async def test_retiring_survives_a_callback_that_names_no_channel(pub_server):
    """
    Not every caller is a PubServerChannel -- tests and other transports
    pass plain functions.  Failing to find one must not turn a reader
    shutdown into an exception.
    """

    async def presence_callback(subscriber, msg):
        pass

    pub_server.daemon_pub_sock = FakeSubSocket([])
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )


async def test_an_implausibly_long_topic_is_rejected_before_decoding(
    pub_server, pki_dir
):
    """
    Decoding costs several times the frame's size and the frames arrive
    from unauthenticated peers, so the length is checked before paying for
    it.  An over-long topic would fail to resolve either way, so what is
    asserted here is that the reader never got as far as trying.
    """
    added = []

    async def presence_callback(subscriber, msg):
        added.append(subscriber.id_)

    pub_server.daemon_pub_sock = FakeSubSocket([FakeFrame(b"\x01" + b"a" * 100000)])
    with patch.object(
        pub_server, "_topic_to_minion", side_effect=AssertionError("decoded it")
    ) as resolve:
        await asyncio.wait_for(
            pub_server._subscription_presence(presence_callback, lambda s: None),
            timeout=10,
        )

    assert resolve.call_count == 0, "the oversized topic reached the resolver"
    assert added == []


def test_a_real_peer_can_forge_a_subscription_frame(bound_pub_server, io_loop):
    """
    Pins the hazard, because it is the reason this transport's presence is
    advisory and the reason ``max_minions`` must not be trusted to it.

    libzmq interprets only the first part of an upstream multipart message
    as a subscription command; the rest are handed to the application. It
    pushes real notifications with their flags cleared -- and does the same
    to a subscription-shaped continuation part -- so MORE does not separate
    forged frames from genuine ones. An earlier version of the reader tried
    to drop continuations and was defeated by the three-part form below.

    If libzmq ever stops delivering these, or starts marking them, this
    test fails and a real defence becomes possible. Measure before
    assuming one.
    """
    context = zmq.Context()
    sub = atk = None
    try:
        _, pub_sock, monitor = bound_pub_server._get_sockets(
            context, io_loop, subscriptions=True
        )
        sub = context.socket(zmq.SUB)
        sub.setsockopt(zmq.SUBSCRIBE, b"victim")
        sub.connect(bound_pub_server.pub_uri)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if pub_sock.poll(100) and pub_sock.recv() == b"\x01victim":
                break
        else:
            pytest.fail("the real subscribe never arrived")

        atk = context.socket(zmq.XSUB)
        atk.setsockopt(zmq.ONLY_FIRST_SUBSCRIBE, 1)
        atk.connect(bound_pub_server.pub_uri)
        time.sleep(0.5)
        while pub_sock.poll(100):
            pub_sock.recv()

        atk.send_multipart([b"payload", b"\x01junk", b"\x00victim"])
        frames = []
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(frames) < 3:
            if pub_sock.poll(100):
                frames.append(pub_sock.recv(copy=False))

        assert [bytes(f) for f in frames] == [b"payload", b"\x01junk", b"\x00victim"]
        assert [f.more for f in frames] == [True, False, False], (
            "libzmq clears MORE on subscription-shaped parts, which is why"
            " they cannot be told apart from genuine notifications"
        )
        monitor.stop()
    finally:
        for s_ in (sub, atk):
            if s_ is not None:
                s_.close()
        context.destroy(linger=0)


def test_the_topic_map_rebuild_is_debounced(pub_server, sessions, pki_dir):
    """
    The accepted-keys mtime changes on every accepted key, so under
    ``auto_accept`` a reconnect storm would rebuild the map on essentially
    every subscription -- a listdir and a dict the size of the fleet each
    time, on the loop that publishes every job.  Memoising the hashes fixed
    only the hashing; the rest is still O(fleet) per rebuild.
    """
    _authenticate(sessions, "minion-one")
    pub_server._topic_to_minion(_presence_topic(sessions, "minion-one"))

    with patch.object(
        pub_server, "_read_topic_map", wraps=pub_server._read_topic_map
    ) as rebuild:
        for n in range(20):
            _authenticate(sessions, f"minion-{n}")
            pub_server._topic_to_minion(_hexid(f"minion-{n}"))

    assert rebuild.call_count == 0, (
        "twenty key changes in well under the minimum interval must not"
        " cause twenty rebuilds"
    )


def test_a_failed_listing_is_not_cached(pub_server, sessions, pki_dir):
    """
    A transient ``listdir`` failure -- EMFILE during a reconnect storm --
    must not pin an empty map in place until the directory changes again.
    Every subscription arriving in that window would be dropped, and
    permanently, since libzmq delivers each SUBSCRIBE exactly once.
    """
    _authenticate(sessions, "minion-one")
    pub_server._topic_map_min_interval = 0

    with patch("os.listdir", side_effect=OSError("EMFILE")):
        assert (
            pub_server._topic_to_minion(_presence_topic(sessions, "minion-one")) is None
        )

    assert (
        pub_server._topic_to_minion(_presence_topic(sessions, "minion-one"))
        == "minion-one"
    ), "the failed read was cached and the map never recovered"


async def test_a_subscription_that_did_not_resolve_is_retried(
    pub_server, sessions, pki_dir
):
    """
    libzmq delivers each SUBSCRIBE exactly once.  A minion that subscribes
    while its key is not yet visible -- auto_accept, a shared
    ``cluster_pki_dir`` on NFS, a transient listing failure -- would
    otherwise be invisible for the life of its connection, and the record
    would keep heartbeating from the minions that did register, so it would
    stay settled and nothing would fall back.
    """
    added = []

    async def presence_callback(subscriber, msg):
        added.append((subscriber.id_, subscriber.address))

    pub_server._topic_map_min_interval = 0
    _authenticate(sessions, "early-minion")
    topic_s, reveal = _authenticated_but_unseen(sessions, "late-minion")
    topic = topic_s.encode()
    other = _presence_topic(sessions, "early-minion").encode()

    class _AcceptsLate(FakeSubSocket):
        """Accepts the key between the two frames, not before either."""

        async def recv(self, copy=True):
            if self.recv_count == 1:
                reveal()
            return await super().recv(copy=copy)

    pub_server.daemon_pub_sock = _AcceptsLate(
        [
            FakeFrame(b"\x01" + topic, address="10.0.0.9"),
            FakeFrame(b"\x01" + other, address="10.0.0.8"),
        ]
    )
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )

    assert ("late-minion", "10.0.0.9") in added, f"never recovered: {added}"


def test_only_plausible_topics_are_parked(pub_server, sessions):
    """
    A topic that is not a hex digest can never resolve however long it
    is kept, so keeping it only uses up a slot an unauthenticated peer
    would otherwise have to compete for.
    """
    pub_server._park_unresolved("not-a-digest", "")
    pub_server._park_unresolved("deadbeef", "")
    assert pub_server._unresolved == {}

    _authenticate(sessions, "minion-one")
    _authenticate(sessions, "minion-two")
    good = _presence_topic(sessions, "minion-one")
    pub_server._park_unresolved(good, "10.0.0.1")
    pub_server._park_unresolved(_presence_topic(sessions, "minion-two"), "10.0.0.2")
    assert list(pub_server._unresolved) == [
        good,
        _presence_topic(sessions, "minion-two"),
    ]


def test_unresolved_topics_cannot_grow_without_bound(pub_server):
    """
    Parked topics arrive from unauthenticated peers. The cap has to hold
    even when every one of them is the right shape -- which an attacker
    can manage, since the shape is just hex of the right length.
    """
    for n in range(pub_server._max_unresolved + 50):
        pub_server._park_unresolved(
            PREFIX + hashlib.sha256(f"m{n}".encode()).hexdigest(), "10.0.0.1:1"
        )

    assert len(pub_server._unresolved) == pub_server._max_unresolved


def test_minions_behind_one_nat_do_not_evict_each_other(pub_server):
    """
    The publish server sees the gateway's address for every minion behind
    a NAT -- that is the entire situation this feature exists for. Any
    per-source-address cap on parking therefore truncates exactly the
    fleet it is meant to protect, and silently: libzmq delivers each
    SUBSCRIBE once, so an evicted minion is invisible for the life of its
    connection.
    """
    gateway = "198.51.100.4:51000"
    topics = [
        PREFIX + hashlib.sha256(f"natted-{n}".encode()).hexdigest() for n in range(5000)
    ]
    for topic in topics:
        pub_server._park_unresolved(topic, gateway)

    assert len(pub_server._unresolved) == 5000, (
        f"only {len(pub_server._unresolved)} of 5000 NAT'd minions are "
        "parked; the rest were evicted by their own neighbours"
    )
    assert all(t in pub_server._unresolved for t in topics)


def test_a_flood_cannot_evict_a_real_minion_that_is_waiting(pub_server):
    """
    The attack a global oldest-out policy allows, and the reason parking
    is capped per address.

    A minion that parked legitimately -- it subscribed inside the rebuild
    debounce, which is routine on any auth churn -- is *older* than
    anything invented afterwards. Under oldest-out, an unauthenticated
    peer that can reach the publish port evicts it by flooding, and
    libzmq never redelivers a SUBSCRIBE, so that minion is invisible for
    the life of its connection.
    """
    victim = PREFIX + hashlib.sha256(b"the-real-minion").hexdigest()
    pub_server._park_unresolved(victim, "10.0.0.1:5555")

    for n in range(pub_server._max_unresolved + 500):
        pub_server._park_unresolved(
            PREFIX + hashlib.sha256(f"junk{n}".encode()).hexdigest(), "10.9.9.9:666"
        )

    assert victim in pub_server._unresolved, (
        "an unauthenticated peer evicted a real minion by flooding; it is "
        "now invisible for the life of its connection"
    )


def test_a_flood_from_many_addresses_still_cannot_evict_a_real_minion(pub_server):
    """
    The per-address cap alone would let an attacker holding many source
    addresses reach the global cap and resume evicting. The global
    backstop therefore takes from whichever address holds the most, which
    is the one that can least claim to be a victim.
    """
    victim = PREFIX + hashlib.sha256(b"the-real-minion").hexdigest()
    pub_server._park_unresolved(victim, "10.0.0.1:5555")

    for n in range(pub_server._max_unresolved * 2):
        pub_server._park_unresolved(
            PREFIX + hashlib.sha256(f"junk{n}".encode()).hexdigest(),
            f"10.9.{n // 250 % 250}.{n % 250}:666",
        )

    assert victim in pub_server._unresolved


async def test_the_socket_is_still_drained_after_presence_is_given_up(
    pub_server, sessions, pki_dir
):
    """
    Giving up on presence does not make the socket stop being an XPUB, and
    it is still being published on.  libzmq keeps moving subscription
    traffic off the inbound pipes into a queue it never bounds -- RCVHWM
    bounds the pipes, not that queue -- so an XPUB nobody reads grows for
    the life of the publish daemon.  That is precisely why ``_get_sockets``
    refuses to open one without a reader.
    """
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one").encode()

    class _FailsThenDelivers(FakeSubSocket):
        """Fails the handling ten times, then has traffic still arriving."""

        def __init__(self):
            super().__init__([])
            self.drained = 0

        async def recv(self, copy=True):
            self.recv_count += 1
            if self.recv_count <= 10:
                raise RuntimeError("handling is broken")
            self.drained += 1
            if self.drained > 5:
                raise zmq.error.ZMQError(zmq.ENOTSOCK)
            return FakeFrame(b"\x01" + topic)

    sock = _FailsThenDelivers()
    pub_server.daemon_pub_sock = sock
    added = []

    async def presence_callback(subscriber, msg):
        added.append(subscriber.id_)

    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )

    assert sock.drained > 5, "the queue was left unread"
    assert added == [], "nothing should be interpreted after giving up"


async def test_the_error_budget_is_consecutive_not_cumulative(
    pub_server, sessions, pki_dir
):
    """
    Ten failures in a row mean something is persistently wrong.  Ten
    failures spread over the life of a publish daemon mean nothing at all,
    and a long-lived master would eventually retire presence over a handful
    of unrelated hiccups.
    """
    _authenticate(sessions, "minion-one")
    _authenticate(sessions, "minion-two")

    class _Flaky(FakeSubSocket):
        """Nine failures, a success, nine more failures, a success."""

        def __init__(self):
            super().__init__([])
            self.script = (
                [None] * 9
                + [b"\x01" + _presence_topic(sessions, "minion-one").encode()]
                + [None] * 9
                + [b"\x01" + _presence_topic(sessions, "minion-two").encode()]
            )

        async def recv(self, copy=True):
            self.recv_count += 1
            if not self.script:
                raise zmq.error.ZMQError(zmq.ENOTSOCK)
            item = self.script.pop(0)
            if item is None:
                raise RuntimeError("hiccup")
            return FakeFrame(item)

    pub_server.daemon_pub_sock = _Flaky()
    added = []

    async def presence_callback(subscriber, msg):
        added.append(subscriber.id_)

    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )

    assert added == ["minion-one", "minion-two"], (
        "a successful read must reset the budget; eighteen scattered"
        " failures are not a persistent fault"
    )


async def test_a_repeated_subscribe_does_not_leave_a_second_stub(
    pub_server, sessions, pki_dir
):
    """
    One topic, one stub.  A second stub for the same topic would survive the
    single unsubscribe libzmq sends when the last subscriber goes, so the
    channel would hold the minion present for the life of the daemon.

    Asserted through the presence callbacks rather than on
    ``pub_server._present`` alone -- what matters is what the channel ends
    up believing.
    """
    _authenticate(sessions, "minion-one")
    topic = b"\x01" + _presence_topic(sessions, "minion-one").encode()
    untopic = b"\x00" + _presence_topic(sessions, "minion-one").encode()
    # Driven through the channel's own bookkeeping: ``_present`` is keyed by
    # topic either way, so a duplicate stub is invisible there. It is the
    # channel that holds a *set* of subscribers per id, and a second stub
    # object survives the single unsubscribe libzmq sends.
    channel = server.PubServerChannel.__new__(server.PubServerChannel)
    channel.opts = {"cachedir": str(pki_dir.parent)}
    channel.presence_events = False
    channel.event = MagicMock()
    channel._init_presence()

    pub_server.daemon_pub_sock = FakeSubSocket([topic, topic, untopic])
    await asyncio.wait_for(
        pub_server._subscription_presence(
            channel.presence_callback, channel.remove_presence_callback
        ),
        timeout=10,
    )

    assert pub_server._present == {}, "the stub outlived its unsubscribe"
    assert channel.present == {}, (
        "a second stub for one topic survives the single unsubscribe libzmq"
        " sends, so the minion stays present for the life of the daemon"
    )


def test_the_topic_map_has_a_time_based_backstop(pub_server, sessions, pki_dir):
    """
    mtime granularity can hide a change -- two writes inside one filesystem
    tick look identical.  The interval bounds how long a stale map, and so
    a deleted key, keeps being believed.
    """
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one")
    assert pub_server._topic_to_minion(topic) == "minion-one"

    # The accepted key is the only input, so that is what has to go.
    (pki_dir / "minions" / "minion-one").unlink()
    # Freeze the *directory* mtime, which is the rebuild trigger, so that
    # solely the backstop can fire -- exactly the case where the
    # filesystem's timestamp granularity hid the change.
    # The rebuild trigger is a pair: the sessions directory and the
    # accepted-keys directory. Freeze both at the values the last rebuild
    # saw, so only the backstop can fire -- the case where the
    # filesystem's timestamp granularity hid the change. Per-file stats
    # must still work, since the rebuild reads them.
    frozen = pub_server._topic_map_stamp
    real_stat = os.stat
    accepted_dir = str(pki_dir / "minions")

    def _frozen_dir(path, *a, **kw):
        if str(path) == accepted_dir:
            return type("S", (), {"st_mtime_ns": frozen})()
        return real_stat(path, *a, **kw)

    with patch.object(type(pub_server), "_topic_map_min_interval", 0), patch(
        "os.stat", side_effect=_frozen_dir
    ):
        assert pub_server._topic_to_minion(topic) == "minion-one"
        pub_server._topic_map_built -= pub_server._topic_map_interval + 1
        assert pub_server._topic_to_minion(topic) is None
    assert pub_server._topic_map_interval <= 300, (
        "the backstop is how long a deleted key can keep resolving; an"
        " interval this is free to grow without bound is not a backstop"
    )


def test_close_cancels_the_subscription_reader(pub_server):
    """
    The reader holds the socket it is about to have destroyed underneath
    it.  Leaving the task pending behind a dead socket is how asyncio ends
    up complaining about a task that was never retrieved.
    """
    task = MagicMock()
    pub_server._presence_task = task
    pub_server.daemon_pub_sock = None
    pub_server.daemon_pull_sock = None
    pub_server.daemon_monitor = None
    pub_server.daemon_context = None

    pub_server.close()

    assert task.cancel.called, "the reader task was left pending"
    assert pub_server._presence_task is None


async def test_a_subscription_whose_callback_raised_is_retried(
    pub_server, sessions, pki_dir
):
    """
    The stub goes into ``_present`` before the callback is awaited, so a
    callback that raises leaves the transport believing the minion is
    recorded while the channel never heard about it -- and libzmq will not
    deliver that SUBSCRIBE again.  The retry skips any topic already in
    ``_present``, so the stub has to come back out when the callback fails
    or parking it achieves nothing.
    """
    _authenticate(sessions, "minion-one")
    _authenticate(sessions, "minion-two")
    pub_server._topic_map_min_interval = 0
    topic = _presence_topic(sessions, "minion-one").encode()
    other = _presence_topic(sessions, "minion-two").encode()
    seen = []

    async def presence_callback(subscriber, msg):
        seen.append(subscriber.id_)
        if len(seen) == 1:
            raise RuntimeError("the channel was busy")

    class _TouchesKeys(FakeSubSocket):
        """Changes the key directory so the next lookup rebuilds the map."""

        async def recv(self, copy=True):
            if self.recv_count == 1:
                _authenticate(sessions, "minion-three")
            return await super().recv(copy=copy)

    pub_server.daemon_pub_sock = _TouchesKeys(
        [FakeFrame(b"\x01" + topic), FakeFrame(b"\x01" + other)]
    )
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )

    assert (
        seen.count("minion-one") == 2
    ), f"the failed subscribe was never retried: {seen}"


async def test_parked_topics_are_only_swept_after_a_rebuild(
    pub_server, sessions, pki_dir
):
    """
    The sweep runs after every subscription-shaped frame, and nothing but a
    rebuild can change its answer.  Re-scanning regardless costs a lookup
    per parked topic per message -- and the parked set is filled by
    unauthenticated peers, so that is their lever on the loop that
    publishes every job.
    """
    import hashlib

    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one").encode()
    for n in range(50):
        pub_server._park_unresolved(
            PREFIX + hashlib.sha256(f"junk{n}".encode()).hexdigest(), ""
        )
    assert len(pub_server._unresolved) == 50

    class _CountingMap(dict):
        gets = 0

        def get(self, *args):
            type(self).gets += 1
            return dict.get(self, *args)

    async def presence_callback(subscriber, msg):
        pass

    # Prime the map, then swap in the counter so only steady-state lookups
    # are measured.
    pub_server._topic_to_minion(_presence_topic(sessions, "minion-one"))
    pub_server._topic_map = _CountingMap(pub_server._topic_map)
    # Mark the parked set as already swept against this map, so any lookup
    # of a parked topic from here on is a re-scan that cannot succeed.
    pub_server._unresolved_generation = pub_server._topic_map_generation
    _CountingMap.gets = 0

    pub_server.daemon_pub_sock = FakeSubSocket([FakeFrame(b"\x01" + topic)] * 10)
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )

    # 10 resolves, one per frame, plus at most one pass over ``_present``
    # from the generation-gated revocation prune. What must NOT appear is
    # anything proportional to the 50 parked topics, which is what a sweep
    # re-scanning an unchanged map would cost -- and the parked set is
    # filled by unauthenticated peers.
    assert _CountingMap.gets <= 10 + len(pub_server._present), (
        f"{_CountingMap.gets} lookups for 10 frames with 50 parked topics;"
        " one per frame is the resolve, anything more is the sweep"
        " re-scanning a map that has not changed"
    )


async def test_an_unexpected_failure_still_drains_the_socket(pub_server):
    """
    The drain exists because an XPUB nobody reads grows for the life of the
    publish daemon.  That is true however the reader stopped, including
    ways nothing below the per-frame handler anticipated.
    """
    pub_server.daemon_pub_sock = FakeSubSocket([])
    with patch.object(
        pub_server,
        "_subscription_presence_loop",
        side_effect=RuntimeError("something nobody predicted"),
    ), patch.object(pub_server, "_drain_subscriptions", new=AsyncMock()) as drain:
        await asyncio.wait_for(
            pub_server._subscription_presence(lambda s, m: None, lambda s: None),
            timeout=10,
        )

    assert drain.called, "the socket was left unread after an unexpected failure"


async def test_a_retry_whose_callback_raises_keeps_the_topic_parked(
    pub_server, sessions, pki_dir
):
    """
    The sweep consumes the parked entry before invoking the callback, and
    libzmq will not redeliver the SUBSCRIBE.  If the callback raises and
    nothing re-parks the topic, that was the subscription's last chance:
    the stub sits in ``_present``, which the sweep skips, so the channel
    never hears about the minion again.
    """
    _authenticate(sessions, "trigger")
    parked, reveal = _authenticated_but_unseen(sessions, "late-one")
    pub_server._topic_map_min_interval = 0
    pub_server._park_unresolved(parked, "10.0.0.9")
    reveal()

    recorded = []

    async def presence_callback(subscriber, msg):
        if subscriber.id_ == "late-one":
            raise RuntimeError("the channel was busy")
        recorded.append(subscriber.id_)

    pub_server.daemon_pub_sock = FakeSubSocket(
        [FakeFrame(b"\x01" + _presence_topic(sessions, "trigger").encode())]
    )
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )

    assert recorded == ["trigger"]
    assert parked in pub_server._unresolved, "the failed retry lost the minion"
    assert parked not in pub_server._present, "a stub was left behind"


async def test_one_failing_retry_does_not_abandon_the_rest(
    pub_server, sessions, pki_dir
):
    """
    The sweep is a loop over independent subscriptions; one raising
    callback must not cost the others their turn.
    """
    pub_server._topic_map_min_interval = 0
    for name in ("trigger", "bad-one", "good-one"):
        _authenticate(sessions, name)
    pub_server._park_unresolved(_presence_topic(sessions, "bad-one"), "")
    pub_server._park_unresolved(_presence_topic(sessions, "good-one"), "")

    recorded = []

    async def presence_callback(subscriber, msg):
        if subscriber.id_ == "bad-one":
            raise RuntimeError("nope")
        recorded.append(subscriber.id_)

    pub_server.daemon_pub_sock = FakeSubSocket(
        [FakeFrame(b"\x01" + _presence_topic(sessions, "trigger").encode())]
    )
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )

    assert "good-one" in recorded, f"the sweep stopped at the failure: {recorded}"


async def test_a_key_accepted_inside_the_debounce_is_still_named(
    pub_server, sessions, pki_dir
):
    """
    The rebuild is debounced, so a key accepted inside that window is
    invisible to the lookup that just failed.  Recovery is driven by a
    timer rather than by later traffic, because the subscription that
    needs retrying is often the *last* to arrive -- the tail of an
    ``auto_accept`` storm, or a lone minion on a quiet fleet -- and
    nothing follows it to trigger a frame-driven sweep.
    """
    added = []

    async def presence_callback(subscriber, msg):
        added.append(subscriber.id_)

    pub_server._topic_map_min_interval = 0.05
    topic, reveal = _authenticated_but_unseen(sessions, "late-one")

    # The subscribe arrives before the master can see the key, and nothing
    # follows it.
    pub_server.daemon_pub_sock = FakeSubSocket(
        [FakeFrame(b"\x01" + topic.encode(), address="10.0.0.9")]
    )
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )
    assert added == [], "cannot be named yet"
    assert topic in pub_server._unresolved

    # The key becomes visible. The sweeper, not another frame, recovers it.
    # Re-authenticating would mint a *different* key, and so a different
    # topic, which is exactly what must not be needed here.
    reveal()
    pub_server._ensure_sweeper(presence_callback)
    for _ in range(100):
        await asyncio.sleep(0.05)
        if added:
            break
    if pub_server._sweeper is not None:
        pub_server._sweeper.cancel()

    assert added == ["late-one"], "the sweeper never recovered it"


def test_the_subscription_socket_caps_inbound_messages(bound_pub_server, io_loop):
    """
    An XPUB keeps what its subscribers send upstream, unlike a PUB, and
    ZeroMQ places no limit on a message by default -- so without this an
    unauthenticated peer sizes the publish daemon's memory.  The cap is
    inbound only; published jobs are unaffected.
    """
    context = zmq.Context()
    try:
        _, pub_sock, monitor = bound_pub_server._get_sockets(
            context, io_loop, subscriptions=True
        )
        assert (
            pub_sock.getsockopt(zmq.MAXMSGSIZE)
            == salt.transport.zeromq._MAX_SUBSCRIPTION_MSG
        )
        monitor.stop()
    finally:
        context.destroy(linger=0)


async def test_an_unsubscribe_clears_a_still_parked_topic(
    pub_server, sessions, pki_dir
):
    """
    A minion that subscribed before its key was visible is parked.  If it
    then disconnects, libzmq delivers the unsubscribe -- but the parked
    entry would outlive it, and a later rebuild would resolve it and
    report the minion present after it had gone, with no further
    unsubscribe ever coming.
    """
    pub_server._topic_map_min_interval = 0
    topic, reveal = _authenticated_but_unseen(sessions, "late-one")
    added, removed = [], []

    async def presence_callback(subscriber, msg):
        added.append(subscriber.id_)

    def remove_presence_callback(subscriber):
        removed.append(subscriber.id_)

    pub_server.daemon_pub_sock = FakeSubSocket(
        [FakeFrame(b"\x01" + topic.encode()), FakeFrame(b"\x00" + topic.encode())]
    )
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, remove_presence_callback),
        timeout=10,
    )
    assert pub_server._unresolved == {}, "the departed minion is still parked"

    # The key appears afterwards; nothing must resurrect it.
    reveal()
    pub_server._topic_to_minion(topic)
    await pub_server._retry_unresolved(presence_callback)
    assert added == [], f"a departed minion was reported present: {added}"


def test_unresolvable_topics_do_not_drive_a_rebuild_per_frame(
    pub_server, sessions, pki_dir
):
    """
    The topics that fail to resolve are the ones an unauthenticated peer
    invented, so if parking rebuilt the map the peer would be driving a
    ``listdir`` plus a fleet-sized dict per frame, on the loop that
    publishes every job.  Sending them is microseconds; serving them was
    milliseconds -- a few hundred-fold amplification needing nothing but
    TCP reachability to the publish port.

    The topics here are the right *shape* (sixty-four hex characters), which is
    what makes them park at all -- an earlier version of this test used
    ``unknown-topic-N``, which ``_could_name_a_minion`` rejects, so it
    never exercised parking and passed for the wrong reason.
    """
    import hashlib

    for n in range(50):
        _authenticate(sessions, f"minion-{n}")
    pub_server._topic_to_minion(_presence_topic(sessions, "minion-0"))

    with patch.object(
        pub_server, "_read_topic_map", wraps=pub_server._read_topic_map
    ) as rebuild:
        for n in range(100):
            topic = PREFIX + hashlib.sha256(f"junk{n}".encode()).hexdigest()
            assert pub_server._topic_to_minion(topic) is None
            pub_server._park_unresolved(topic, "")

    assert rebuild.call_count == 0, (
        f"{rebuild.call_count} rebuilds for 100 junk frames -- parking must"
        " not invalidate the map"
    )


async def test_a_delivery_topic_is_not_an_identity(pub_server, sessions, pki_dir):
    """
    ``zmq_filtering`` makes a minion subscribe to ``sha1(its id)`` for
    delivery.  That names it, but it does not *prove* anything: the id is
    usually a hostname, so honouring it would let anything able to reach
    the publish port claim presence for any minion -- and cancel the
    subscription of one really connected.

    The cost is that a minion too old to announce itself cannot be seen at
    all, where ``zmq_filtering`` used to cover it. That is the trade: a
    forgeable identity is worse than a missing one, because the answer is
    then confidently wrong rather than visibly incomplete.
    """
    _authenticate(sessions, "minion-one")
    delivery = _hexid("minion-one").encode()

    added, removed = await _drain(pub_server, [b"\x01" + delivery, b"\x00" + delivery])

    assert added == []
    assert removed == []


def test_the_topic_depends_on_the_minion_id(opts):
    """
    One secret serves the whole fleet, so the id has to be what
    distinguishes one minion's topic from another's -- otherwise every
    minion would be told the same topic and could announce a neighbour.
    """
    one = salt.utils.presence.topic_for(opts, "minion-one")
    two = salt.utils.presence.topic_for(opts, "minion-two")

    assert one != two
    assert "minion-one" not in one, "the topic leaks the id it names"


def test_a_minion_cannot_announce_another_minion(pub_server, opts):
    """
    A minion is *handed* its topic and never derives one, so producing a
    neighbour's would mean holding the master's presence secret. This is
    what separates "a compromised minion" from "a compromised fleet".

    Checked by computing a victim's topic under a different secret --
    which is the best an attacker holding one minion's assignment can
    do -- and confirming the master does not accept it.
    """
    import hmac as _hmac

    forged = (
        PREFIX
        + _hmac.new(
            b"a-secret-the-master-does-not-have", b"victim", hashlib.sha256
        ).hexdigest()
    )
    (pathlib.Path(opts["pki_dir"]) / "minions" / "victim").write_text("KEY")

    assert pub_server._topic_to_minion(forged) is None
    assert (
        pub_server._topic_to_minion(
            PREFIX + salt.utils.presence.topic_for(opts, "victim")
        )
        == "victim"
    )


def test_announcing_on_a_closed_connection_is_harmless():
    """
    ``close`` drops the socket, and announcing afterwards must not raise
    -- the caller has no way to know the connection has gone.
    """
    client = salt.transport.zeromq.PublishClient.__new__(
        salt.transport.zeromq.PublishClient
    )
    client._socket = None
    client._announced_topic = None
    client._connect_called = False

    client.announce_presence("a" * 64)

    assert client._announced_topic is None, "it recorded a topic it never sent"


async def test_a_topic_that_never_resolves_is_eventually_given_up_on(
    pub_server, sessions
):
    """
    The sweeper forces a topic-map rebuild -- a listdir and a stat per
    minion -- once per tick for as long as anything is parked, and a
    topic an unauthenticated peer invented resolves on no rebuild ever.
    Without a deadline, one junk frame buys that rebuild for the life of
    the publish daemon.
    """
    pub_server._park_unresolved(_unknown_topic(), "10.0.0.1:1234")
    assert pub_server._unresolved

    pub_server._expire_unresolved()
    assert pub_server._unresolved, "given up on before the deadline"

    topic, (address, _) = next(iter(pub_server._unresolved.items()))
    pub_server._unresolved[topic] = (address, time.monotonic() - 1)
    pub_server._expire_unresolved()

    assert not pub_server._unresolved, "parked forever; the sweeper never stops"


async def test_the_sweeper_stops_once_everything_has_expired(pub_server, sessions):
    """
    The point of the expiry: the loop has to end, or it goes on forcing
    rebuilds on the loop that publishes every job.
    """
    pub_server._topic_map_min_interval = 0.01
    pub_server._unresolved_ttl = 0.05

    pub_server._park_unresolved(_unknown_topic(), "10.0.0.1:1234")
    pub_server._ensure_sweeper(AsyncMock())
    sweeper = pub_server._sweeper
    assert sweeper is not None

    await asyncio.wait_for(sweeper, timeout=10)

    assert not pub_server._unresolved
    assert pub_server._sweeper is None


def test_a_whole_fleet_can_park_at_once(pub_server, sessions):
    """
    The only thing that parks a legitimate topic is losing the race with
    the memoised topic map -- and a master restart loses it for every
    minion at the same moment. A cap below fleet size would evict real
    minions, each of which is then invisible for the life of its
    connection, because libzmq sends a SUBSCRIBE exactly once.
    """
    assert pub_server._max_unresolved >= 10000, (
        "the cap is below the size of fleets Salt is routinely run at; "
        "a mass reconnect would evict real minions"
    )


async def test_a_revoked_key_retracts_a_connected_minion(pub_server, sessions, pki_dir):
    """
    ``salt-key -d`` on a minion that is still connected must take it out
    of presence.

    The accepted-key check only runs on the SUBSCRIBE edge, so without a
    prune the minion stays in ``_present`` -- and so in
    ``connected_ids()`` and in ``max_minions`` -- until its TCP connection
    drops, which the operator revoking the key cannot force. Address
    matching, which this replaces, did not have that hole: ``salt-key -d``
    flushes the grains cache that matching reads.
    """
    _authenticate(sessions, "minion-one")
    _authenticate(sessions, "minion-two")
    topic_one = _presence_topic(sessions, "minion-one").encode()
    topic_two = _presence_topic(sessions, "minion-two").encode()
    pub_server._topic_map_min_interval = 0

    added, removed = [], []

    async def presence_callback(subscriber, msg):
        added.append(subscriber.id_)
        if subscriber.id_ == "minion-one":
            # The operator revokes it while it is connected.
            (pki_dir / "minions" / "minion-one").unlink()

    pub_server.daemon_pub_sock = FakeSubSocket(
        [b"\x01" + topic_one, b"\x01" + topic_two]
    )
    await asyncio.wait_for(
        pub_server._subscription_presence(
            presence_callback, lambda subscriber: removed.append(subscriber.id_)
        ),
        timeout=10,
    )

    assert added == ["minion-one", "minion-two"]
    assert removed == ["minion-one"], (
        "a revoked minion is still being reported present; it also still "
        "counts against max_minions"
    )
    assert {s.id_ for s in pub_server._present.values()} == {"minion-two"}


async def test_an_unreadable_key_directory_does_not_retract_the_fleet(
    pub_server, sessions, pki_dir
):
    """
    A failed listdir yields an empty topic map. Pruning against that would
    read as "every key has been revoked" and retract every connected
    minion at once -- turning a transient filesystem error into a
    fleet-wide outage of presence.
    """
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one").encode()
    pub_server._topic_map_min_interval = 0

    removed = []

    async def presence_callback(subscriber, msg):
        # The directory becomes unreadable while it is connected.
        shutil.rmtree(str(pki_dir / "minions"))

    pub_server.daemon_pub_sock = FakeSubSocket([b"\x01" + topic, b"\x01" + topic])
    await asyncio.wait_for(
        pub_server._subscription_presence(
            presence_callback, lambda subscriber: removed.append(subscriber.id_)
        ),
        timeout=10,
    )

    assert removed == [], "a transient listdir failure retracted the fleet"


async def test_the_reader_arms_the_sweeper_when_it_parks(pub_server, sessions):
    """
    Parking without arming the sweeper loses the minion: libzmq delivers
    each SUBSCRIBE exactly once, and the retry only runs when something
    drives it. The one test that covered the sweeper called
    ``_ensure_sweeper`` by hand after the reader had already returned, so
    removing the call from the reader passed the whole suite.
    """
    topic = _unknown_topic("minion-one").encode()
    armed = []

    def _ensure(callback):
        armed.append(callback)

    pub_server._ensure_sweeper = _ensure
    pub_server.daemon_pub_sock = FakeSubSocket([b"\x01" + topic])

    async def presence_callback(subscriber, msg):
        pass

    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, None), timeout=10
    )

    assert pub_server._unresolved, "the topic was not parked at all"
    assert armed, "parked a topic without arming the retry that recovers it"


async def test_a_parking_frame_still_reaches_the_end_of_the_loop(
    pub_server, sessions, pki_dir
):
    """
    The rebuild that fails to name an unknown topic is the very same one
    that can reveal a revoked key, so a parking frame must not return
    early from the per-frame handler -- a master being probed with junk
    topics, which is exactly when parking happens, would otherwise stop
    retracting revoked minions.

    Asserted on the control flow rather than on a retraction, because
    revocation is covered by three paths -- this one, the sweeper, and
    the periodic watch -- and an outcome-based test is satisfied by any
    of them. See ``test_a_revoked_key_retracts_a_connected_minion`` and
    ``test_revocation_is_noticed_on_an_idle_master`` for those.
    """
    pub_server._topic_map_min_interval = 0
    pub_server._ensure_sweeper = lambda callback: None

    pruned = []
    real_prune = pub_server._prune_revoked
    pub_server._prune_revoked = lambda cb: pruned.append(1) or real_prune(cb)

    async def presence_callback(subscriber, msg):
        pass

    pub_server.daemon_pub_sock = FakeSubSocket(
        [b"\x01" + _unknown_topic("nobody").encode()]
    )
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, None), timeout=10
    )

    assert pub_server._unresolved, "the frame did not park, so nothing is proven"
    assert pruned, (
        "a parking frame returned early and skipped the revocation prune "
        "at the foot of the loop"
    )


def test_eviction_takes_the_newest_not_the_oldest(pub_server):
    """
    The direction is the whole defence. A legitimate park is always older
    than whatever arrives after it -- it happens when a minion subscribes
    inside the rebuild debounce and clears on the next sweep -- so
    oldest-out hands an unauthenticated flooder the choice of victim, and
    libzmq never redelivers a SUBSCRIBE.
    """
    victim = PREFIX + hashlib.sha256(b"the-real-minion").hexdigest()
    pub_server._park_unresolved(victim, "10.0.0.1:5555")

    for n in range(pub_server._max_unresolved + 500):
        pub_server._park_unresolved(
            PREFIX + hashlib.sha256(f"junk{n}".encode()).hexdigest(), "10.9.9.9:666"
        )

    assert victim in pub_server._unresolved, (
        "an unauthenticated peer evicted a real minion by flooding; it is "
        "now invisible for the life of its connection"
    )
    assert len(pub_server._unresolved) == pub_server._max_unresolved


def test_a_repark_keeps_the_original_deadline(pub_server):
    """
    ``_unresolved_ttl`` exists to guarantee the sweeper terminates. The
    retry re-parks an entry whose presence callback raised, and if that
    restamped the deadline the entry would be refreshed on every tick --
    so a wedged event bus would hold the sweeper open forever, rebuilding
    the topic map on the loop that publishes every job.
    """
    topic = _unknown_topic()
    pub_server._park_unresolved(topic, "10.0.0.1:1")
    original = pub_server._unresolved[topic][1]

    # What the retry's failure path does, a tick later.
    pub_server._park_unresolved(topic, "10.0.0.1:1", deadline=original)

    assert pub_server._unresolved[topic][1] == original, (
        "the re-park restamped the deadline; a callback that keeps "
        "failing now holds the sweeper open forever"
    )


async def test_the_sweeper_terminates_even_if_every_retry_fails(pub_server, sessions):
    """
    End to end: the entry expires and the loop ends.
    """
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one")
    pub_server._topic_map_min_interval = 0.01
    pub_server._unresolved_ttl = 0.3

    async def always_fails(subscriber, msg):
        raise RuntimeError("event bus is unhappy")

    pub_server._park_unresolved(topic, "10.0.0.1:1")
    pub_server._ensure_sweeper(always_fails)
    sweeper = pub_server._sweeper
    assert sweeper is not None

    await asyncio.wait_for(sweeper, timeout=10)

    assert not pub_server._unresolved
    assert pub_server._sweeper is None


async def test_the_sweeper_does_not_force_a_rebuild_per_tick(pub_server, sessions):
    """
    Forcing one cost a full ``listdir`` plus a stat per accepted key
    every tick for the whole TTL -- around sixty O(fleet) rebuilds bought
    with a single well-shaped frame from an unauthenticated peer.
    """
    pub_server._topic_map_min_interval = 0.01
    pub_server._unresolved_ttl = 0.25
    pub_server._park_unresolved(_unknown_topic(), "10.9.9.9:666")

    rebuilds = []
    real = pub_server._read_topic_map

    def counting():
        rebuilds.append(1)
        return real()

    pub_server._read_topic_map = counting
    pub_server._ensure_sweeper(AsyncMock())
    await asyncio.wait_for(pub_server._sweeper, timeout=10)

    assert len(rebuilds) <= 2, (
        f"{len(rebuilds)} topic-map rebuilds from one parked junk topic; "
        "the sweeper is forcing one per tick"
    )


async def test_steady_state_frames_do_not_each_pay_two_stats(pub_server, sessions):
    """
    When the stamp is unchanged and the backstop has not expired there is
    nothing to do, and that is the steady state. Gating the stats on when
    the map was last *rebuilt* rather than last *checked* left the gap
    permanently open: once one rebuild had been skipped,
    ``_topic_map_built`` stopped moving, so every frame thereafter paid
    both syscalls -- work proportional to an unauthenticated peer's frame
    rate, which is the one thing this loop must not have.

    The skipped rebuild is the part that matters; a test that only ever
    rebuilds cannot tell the two gates apart.
    """
    _authenticate(sessions, "minion-one")
    pub_server._topic_map_min_interval = 0.05
    pub_server._topic_to_minion(_presence_topic(sessions, "minion-one"))

    # Let the debounce lapse, then take one frame whose rebuild is
    # skipped because nothing has changed.
    await asyncio.sleep(0.1)
    pub_server._topic_to_minion(_unknown_topic())

    with patch("os.stat", wraps=os.stat) as stat:
        for _ in range(500):
            pub_server._topic_to_minion(_unknown_topic())

    assert stat.call_count == 0, (
        f"{stat.call_count} stat calls for 500 frames arriving inside the "
        "debounce after a skipped rebuild"
    )


async def test_revocation_is_noticed_on_an_idle_master(pub_server, sessions, pki_dir):
    """
    ``salt-key -d`` on a quiet master. No subscription frames arrive --
    libzmq sends one SUBSCRIBE per topic and nothing repeats it -- and
    nothing is parked, so neither of the traffic-driven prune call sites
    ever runs. Without a timer the revoked minion stays in
    ``connected_ids()`` and in ``max_minions`` indefinitely.
    """
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one")
    pub_server._present[topic] = salt.transport.zeromq._SubscriberStub(
        "minion-one", "10.0.0.1:1"
    )
    pub_server._topic_map_interval = 0.05

    removed = []
    watch = asyncio.get_running_loop().create_task(
        pub_server._watch_revocations(lambda stub: removed.append(stub.id_))
    )
    try:
        (pki_dir / "minions" / "minion-one").unlink()
        for _ in range(100):
            await asyncio.sleep(0.02)
            if removed:
                break
    finally:
        watch.cancel()

    assert removed == ["minion-one"], (
        "an idle master never noticed the revocation; the minion stays "
        "in connected_ids() and counts against max_minions"
    )
    assert topic not in pub_server._present


async def test_a_reaccepted_key_restores_presence(pub_server, sessions, pki_dir):
    """
    ``salt-key -d`` then ``salt-key -a`` on a minion that stays connected
    throughout.

    Nothing about a key being removed and restored reaches the
    subscriber: libzmq delivers each SUBSCRIBE exactly once and
    ``announce_presence`` short-circuits on an unchanged topic, so the
    minion sends nothing further. Without re-admission it is absent until
    it restarts or its session key happens to rotate -- up to a whole
    ``publish_session``.
    """
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one")
    key = pki_dir / "minions" / "minion-one"
    pub_server._topic_map_min_interval = 0
    pub_server._topic_map_interval = 0.05

    added, removed = [], []

    async def presence_callback(subscriber, msg):
        added.append(subscriber.id_)

    pub_server._present[topic] = salt.transport.zeromq._SubscriberStub(
        "minion-one", "10.0.0.1:1"
    )

    # salt-key -d
    key.unlink()
    pub_server._maybe_rebuild_topic_map(force=True)
    pub_server._prune_revoked(lambda stub: removed.append(stub.id_))
    assert removed == ["minion-one"]
    assert topic not in pub_server._present

    # salt-key -a, with the minion still connected and silent
    key.write_text("KEY")
    pub_server._maybe_rebuild_topic_map(force=True)
    for stub in pub_server._readmit_restored():
        await presence_callback(stub, None)

    assert added == ["minion-one"], (
        "a re-accepted key did not restore presence; the minion stays "
        "absent until it restarts"
    )
    assert pub_server._present[topic].id_ == "minion-one"


async def test_a_malformed_topic_still_reaches_the_end_of_the_loop(pub_server):
    """
    Same property as the parking case, by the other early-exit path.

    A topic rejected by the shape filter must not return early either:
    probing the publish port with junk is exactly the situation in which
    a master would otherwise stop running the retry and revocation work
    at the foot of the loop.
    """
    pub_server._topic_map_min_interval = 0
    pub_server._ensure_sweeper = lambda callback: None

    pruned = []
    real_prune = pub_server._prune_revoked
    pub_server._prune_revoked = lambda cb: pruned.append(1) or real_prune(cb)

    async def presence_callback(subscriber, msg):
        pass

    pub_server.daemon_pub_sock = FakeSubSocket([b"\x01" + b"not-a-digest"])
    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, None), timeout=10
    )

    assert not pub_server._unresolved, "a malformed topic must not be parked"
    assert pruned, (
        "a malformed topic returned early and skipped the revocation "
        "prune at the foot of the loop"
    )


async def test_a_departure_is_honoured_once_the_topic_stops_resolving(
    pub_server, sessions, pki_dir
):
    """
    The unsubscribe path is keyed by topic and deliberately does not go
    through the map: the stub already carries the id, and the topic
    stops resolving the moment the key is revoked. Resolving on the way
    out would drop the departure and leave the minion reported present
    for the life of the publish daemon.

    The precondition is established by revoking the *accepted key*.
    Rewriting a session key -- which is what this used to do -- no
    longer changes the map at all, so the topic went on resolving and
    the scenario never occurred.
    """
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one").encode()
    pub_server._topic_map_min_interval = 0
    pub_server._ensure_sweeper = lambda callback: None
    pub_server._prune_revoked = lambda cb: None

    removed = []

    class _RevokeBetweenFrames(FakeSubSocket):
        async def recv(self, copy=True):
            if self.recv_count == 1:
                (pki_dir / "minions" / "minion-one").unlink()
                # The unsubscribe path does not rebuild, so without this
                # the revoked topic would still resolve and the test
                # could not tell the two behaviours apart.
                pub_server._maybe_rebuild_topic_map(force=True)
            return await super().recv(copy=copy)

    async def presence_callback(subscriber, msg):
        pass

    pub_server.daemon_pub_sock = _RevokeBetweenFrames(
        [b"\x01" + topic, b"\x00" + topic]
    )
    await asyncio.wait_for(
        pub_server._subscription_presence(
            presence_callback, lambda subscriber: removed.append(subscriber.id_)
        ),
        timeout=10,
    )

    assert removed == ["minion-one"], (
        "the departure was dropped because the topic no longer resolved; "
        "the minion is reported present for the life of the daemon"
    )
    assert pub_server._present == {}


def test_the_presence_secret_is_generated_once_and_kept_private(tmp_path):
    """
    Everything rests on this file. If it changed between reads, every
    minion's topic would move underneath it -- the exact coupling that
    deriving from the session key caused. If it were readable, anyone on
    the box could compute every minion's topic and forge presence.
    """
    opts = {"pki_dir": str(tmp_path)}

    first = salt.utils.presence.presence_secret(opts)
    second = salt.utils.presence.presence_secret(opts)

    assert first == second, "the secret moved between reads"
    assert len(first) >= 32
    path = salt.utils.presence.presence_secret_path(opts)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_two_workers_racing_agree_on_one_secret(tmp_path):
    """
    A master forks several request workers, and the first authentication
    on each can be the one that creates this. If they disagreed, minions
    would be assigned topics their own master could not resolve --
    present or absent depending on which worker answered.
    """
    opts = {"pki_dir": str(tmp_path)}
    real_open = os.open
    created = []

    def racing_open(path, flags, *a, **kw):
        # Another worker wins between our read and our create.
        if flags & os.O_EXCL and not created:
            created.append(True)
            fd = real_open(path, flags, *a, **kw)
            os.write(fd, b"the-other-worker-got-here-first")
            os.close(fd)
        return real_open(path, flags, *a, **kw)

    with patch("os.open", racing_open):
        secret = salt.utils.presence.presence_secret(opts)

    assert (
        secret == b"the-other-worker-got-here-first"
    ), "the loser of the race overwrote or ignored the winner's secret"
    assert salt.utils.presence.presence_secret(opts) == secret


def test_a_cluster_shares_one_secret(tmp_path):
    """
    Cluster peers share a cachedir, and a minion may authenticate to one
    peer while its publish connection lands on another. They have to
    agree on the topic or the second peer cannot name it -- so the secret
    lives beside the shared accepted keys, not in a per-peer directory.
    """
    shared = tmp_path / "cluster_pki"
    shared.mkdir()
    peer_a = {"pki_dir": str(tmp_path / "a"), "cluster_pki_dir": str(shared)}
    peer_b = {"pki_dir": str(tmp_path / "b"), "cluster_pki_dir": str(shared)}
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()

    assert salt.utils.presence.topic_for(
        peer_a, "minion-one"
    ) == salt.utils.presence.topic_for(peer_b, "minion-one")


def test_the_minion_derives_nothing(tmp_path):
    """
    The whole point of assigning the topic: the minion is handed a string
    and subscribes to it. If it computed one instead, the two ends would
    have to agree on an algorithm and on an input that both hold -- which
    is what tied the topic to the rotating session key.
    """
    import salt.channel.client

    channel = salt.channel.client.AsyncPubChannel.__new__(
        salt.channel.client.AsyncPubChannel
    )
    channel.opts = {"id": "minion-one"}
    channel.transport = MagicMock()
    channel.auth = MagicMock()
    channel.auth.creds = {"presence": "the-topic-the-master-assigned"}

    channel._announce_presence()

    channel.transport.announce_presence.assert_called_once_with(
        "the-topic-the-master-assigned"
    )


def test_an_old_master_assigns_nothing_and_nothing_breaks(tmp_path):
    """
    A master too old to assign a topic simply omits the field. The minion
    must not announce, must not raise, and must leave the master to fall
    back to address matching for it.
    """
    import salt.channel.client

    channel = salt.channel.client.AsyncPubChannel.__new__(
        salt.channel.client.AsyncPubChannel
    )
    channel.opts = {"id": "minion-one"}
    channel.transport = MagicMock()
    channel.auth = MagicMock()
    channel.auth.creds = {"aes": "x", "session": "y"}

    channel._announce_presence()

    assert not channel.transport.announce_presence.called


# ---------------------------------------------------------------------------
# The production wiring: master assigns -> minion decrypts -> connect announces.
#
# Each of these three links was deleted in review and the whole suite stayed
# green, because every other test builds the channel by hand and calls
# ``_announce_presence`` directly. Those prove the method forwards a dict
# key; these prove the key gets there and the method is called.
# ---------------------------------------------------------------------------


async def test_connecting_announces(tmp_path):
    """
    ``AsyncPubChannel.connect`` is the only production caller. Removing
    that one line leaves no minion announcing anything, the record empty,
    and ``connected_ids()`` silently back on grain-IP matching -- #66295
    un-fixed, with the suite green.
    """
    import salt.channel.client

    channel = salt.channel.client.AsyncPubChannel.__new__(
        salt.channel.client.AsyncPubChannel
    )
    channel.opts = {"id": "minion-one", "publish_port": 4506}
    channel.auth = MagicMock()
    channel.auth.authenticated = True
    channel.auth.creds = {"presence": "the-assigned-topic", "publish_port": 4505}
    channel.connect_callback = MagicMock()
    channel.disconnect_callback = MagicMock()

    order = []
    channel.transport = MagicMock()
    channel.transport.announce_presence.side_effect = lambda t: order.append(
        ("announce", t)
    )

    async def _connect(*args, **kwargs):
        order.append(("connect", args))

    channel.transport.connect.side_effect = _connect

    await channel.connect()

    assert order and order[0] == (
        "announce",
        "the-assigned-topic",
    ), f"connect() did not announce before connecting; got {order}"
    assert order[1][0] == "connect"


def test_every_auth_reply_branch_assigns_a_topic():
    """
    The master end of the wiring. Four separate branches build the
    encrypted auth reply -- async and sync, each with a token and a
    no-token path -- and a minion whose branch forgets ``presence`` is
    never told a topic, never announces, and is silently invisible.

    Asserted structurally, over the source, because the alternative is
    driving ``_auth_impl`` through key acceptance and autosign for each
    branch; the regression being guarded against is a *missing
    assignment*, which this sees directly. Keyed off ``ret["session"]``
    so a fifth branch added later is covered without editing this test.
    """
    import salt.master

    source = pathlib.Path(salt.master.__file__).read_text()
    tree = ast.parse(source)

    def assigned_keys(node):
        out = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Assign):
                for tgt in sub.targets:
                    if (
                        isinstance(tgt, ast.Subscript)
                        and isinstance(tgt.value, ast.Name)
                        and tgt.value.id == "ret"
                        and isinstance(tgt.slice, ast.Constant)
                    ):
                        out.add(tgt.slice.value)
        return out

    branches = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(func):
            if not isinstance(node, (ast.If, ast.Try)):
                continue
            for body in (getattr(node, "body", []), getattr(node, "orelse", [])):
                keys = assigned_keys(ast.Module(body=body, type_ignores=[]))
                if "session" in keys:
                    branches.append((func.name, node.lineno, keys))

    assert branches, "found no auth-reply branch; this test has gone blind"
    missing = [(f, ln) for f, ln, keys in branches if "presence" not in keys]
    assert not missing, (
        f"auth-reply branches assign ret['session'] but not ret['presence']: "
        f"{missing} -- minions answered by those branches are never told a "
        "topic and can never be named"
    )


def test_the_minion_decrypts_the_assigned_topic(tmp_path):
    """
    The minion end, driven through the real ``handle_signin_response``.

    It must arrive as ``str``: RSA decryption returns bytes, and a bytes
    topic would be subscribed to with a ``b'...'`` wrapper and never
    resolve against anything.
    """
    stub = types.SimpleNamespace(
        opts={
            "pki_dir": str(tmp_path),
            "id": "minion-one",
            "master_uri": "tcp://127.0.0.1:4506",
            "encryption_algorithm": "OAEP-SHA1",
            "signing_algorithm": "PKCS1v15-SHA1",
            "verify_master_pubkey_sign": False,
            "always_verify_signature": False,
        },
        mpub="minion_master.pub",
        # Real RSA decryption returns *bytes*. ``salt.payload.loads`` has
        # already turned the msgpack'd field into ``str`` by this point,
        # so a stub that echoes its input would hand back a ``str`` and
        # the conversion under test would never run.
        get_keys=lambda: types.SimpleNamespace(
            decrypt=lambda d, a=None: salt.utils.stringutils.to_bytes(d)
        ),
        verify_master=lambda *a, **k: b"aes-material",
    )
    # The real shape: the reply carries a msgpack'd, signed ``load``.
    inner = {
        "pub_key": "master-pub",
        "nonce": "a-nonce",
        "aes": b"aes-material",
        "session": b"session-material",
        "presence": b"the-assigned-topic",
        "publish_port": 4505,
    }
    payload = {"load": salt.payload.dumps(inner), "sig": b"sig"}

    creds = salt.crypt.AsyncAuth.handle_signin_response(
        stub, {"id": "minion-one", "nonce": "a-nonce"}, payload
    )

    assert creds["presence"] == "the-assigned-topic"
    assert isinstance(creds["presence"], str), "a bytes topic never resolves"


def test_a_full_parking_table_still_admits_a_real_minion(pub_server):
    """
    The attacker chooses when to send, so he fills the table *first*.
    Evicting ``last=True`` takes the entry just inserted, which means
    every minion that parks while the table is full is discarded on
    arrival -- and libzmq never redelivers a SUBSCRIBE, so each one is
    invisible for the life of its connection.

    Holding the table full costs roughly ``_max_unresolved`` small
    frames per TTL, and needs nothing but TCP reach to the publish port.
    The sibling flood tests park the victim first and so only ever
    exercise the ordering that already worked.
    """
    for n in range(pub_server._max_unresolved):
        pub_server._park_unresolved(
            PREFIX + hashlib.sha256(f"junk{n}".encode()).hexdigest(), "10.9.9.9:666"
        )
    assert len(pub_server._unresolved) == pub_server._max_unresolved

    victim = PREFIX + hashlib.sha256(b"a-real-minion").hexdigest()
    pub_server._park_unresolved(victim, "198.51.100.4:5555")

    assert victim in pub_server._unresolved, (
        "a minion that parked while the table was full was dropped on "
        "arrival; it can never be named again"
    )
    assert len(pub_server._unresolved) == pub_server._max_unresolved


async def test_readmission_does_not_cost_a_stat_per_frame(
    pub_server, sessions, pki_dir
):
    """
    ``_retracted`` is fleet-sized after ``salt-key -D``, and a revoked
    minion has no reason to unsubscribe, so entries persist. Scanning it
    per frame made an unauthenticated peer's frame rate a multiplier on
    fleet-sized filesystem work, on the loop that publishes every job --
    which is precisely what this module's own comments forbid.
    """
    for n in range(300):
        pub_server._retracted[f"topic-{n}"] = salt.transport.zeromq._SubscriberStub(
            f"gone-{n}", "10.0.0.1:1"
        )
    pub_server._topic_map_complete = True
    pub_server._topic_map_min_interval = 60.0
    pub_server._topic_to_minion(_unknown_topic())

    with patch("os.stat", wraps=os.stat) as stat:
        for _ in range(200):
            list(pub_server._readmit_restored())

    # One pass over the 300 retracted entries, plus the directory check.
    # Per-frame scanning would be 200 x 300.
    assert stat.call_count < 1000, (
        f"{stat.call_count} stat calls for 200 frames with 300 retracted "
        "entries -- readmission is running per frame rather than per rebuild"
    )


async def test_the_reader_starts_the_revocation_watch(pub_server, sessions):
    """
    ``_watch_revocations`` is what makes revocation work on an idle
    master -- no frames, nothing parked, so neither traffic-driven prune
    site ever runs. Its own test creates the task by hand, so deleting
    the line that starts it passed the whole suite.

    This is the same defect the suite already records finding once, for
    the sweeper: "The one test that covered the sweeper called
    ``_ensure_sweeper`` by hand after the reader had already returned,
    so removing the call from the reader passed the whole suite." It was
    fixed there and repeated here.
    """
    started = []
    real_watch = pub_server._watch_revocations

    # Recorded when the coroutine is *created*, not when it runs: the
    # reader cancels the task on the way out, so an async wrapper's body
    # would never execute and this would be blind.
    def watching(remove_callback):
        started.append(remove_callback)
        return real_watch(remove_callback)

    pub_server._watch_revocations = watching
    pub_server.daemon_pub_sock = FakeSubSocket([])

    async def presence_callback(subscriber, msg):
        pass

    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )
    await asyncio.sleep(0)

    assert started, (
        "the reader never started the revocation watch; an idle master "
        "would never notice salt-key -d"
    )
    assert pub_server._revocation_watch is None, "and it must be cancelled on exit"


async def test_the_reader_readmits_restored_keys(pub_server, sessions, pki_dir):
    """
    The re-admission generator is driven from three places; its own test
    calls it by hand, so replacing the reader's call with an empty loop
    passed the suite. Without it a key re-accepted by ``salt-key -a``
    waits for the 60-second watch rather than the next frame.
    """
    called = []
    real = pub_server._readmit_restored

    def counting():
        called.append(1)
        return real()

    pub_server._readmit_restored = counting
    _authenticate(sessions, "minion-one")
    pub_server.daemon_pub_sock = FakeSubSocket(
        [b"\x01" + _presence_topic(sessions, "minion-one").encode()]
    )

    async def presence_callback(subscriber, msg):
        pass

    await asyncio.wait_for(
        pub_server._subscription_presence(presence_callback, lambda s: None),
        timeout=10,
    )

    assert called, "the reader never consulted the re-admission generator"


async def test_a_stat_failure_that_is_not_enoent_retracts_nobody(
    pub_server, sessions, pki_dir
):
    """
    Only ENOENT is evidence of revocation.

    This is the guard for the worst defect found against this feature:
    ``os.path.exists`` swallows every OSError and returns False, so a
    key directory that lists but whose children cannot be stat-ed -- an
    NFS EACCES or ESTALE blip, EMFILE, a permissions change -- read as
    "every key revoked" and retracted the entire fleet. There is no
    recovery from that: the stubs are gone and libzmq will not redeliver
    the subscriptions.
    """
    _authenticate(sessions, "minion-one")
    _authenticate(sessions, "minion-two")
    for name in ("minion-one", "minion-two"):
        pub_server._present[_presence_topic(sessions, name)] = (
            salt.transport.zeromq._SubscriberStub(name, "10.0.0.1:1")
        )
    pub_server._maybe_rebuild_topic_map(force=True)
    removed = []

    real_stat = os.stat
    accepted = str(pki_dir / "minions")

    def blipping(path, *a, **kw):
        if str(path).startswith(accepted) and str(path) != accepted:
            raise PermissionError(13, "Permission denied")
        return real_stat(path, *a, **kw)

    with patch("os.stat", blipping):
        pub_server._pruned_generation = -1
        pub_server._prune_revoked(lambda stub: removed.append(stub.id_))

    assert removed == [], (
        f"retracted {removed} on a filesystem error rather than a "
        "revocation; the whole fleet goes and cannot come back"
    )
    assert len(pub_server._present) == 2


async def test_an_incomplete_map_retracts_nobody(pub_server, sessions, pki_dir):
    """
    Belt and braces: ``_prune_revoked`` keys on each id's accepted key
    rather than on the topic map, so an empty map cannot by itself cause
    a retraction. The flag is kept because a failed listing says the
    directory is not readable right now, and the per-id stats about to
    follow are then not worth trusting either.
    """
    _authenticate(sessions, "minion-one")
    topic = _presence_topic(sessions, "minion-one")
    pub_server._present[topic] = salt.transport.zeromq._SubscriberStub(
        "minion-one", "10.0.0.1:1"
    )
    removed = []

    with patch("os.listdir", side_effect=OSError(24, "Too many open files")):
        pub_server._maybe_rebuild_topic_map(force=True)
        assert not pub_server._topic_map_complete
        pub_server._prune_revoked(lambda stub: removed.append(stub.id_))

    assert removed == []
    assert topic in pub_server._present


def test_a_master_that_does_not_use_presence_assigns_no_topic(tmp_path):
    """
    The option is documented as opt-in, but the *issuing* side had no
    gate: every master -- tcp, ws, plain zeromq -- minted a
    ``presence_secret`` on its first authentication, kept it forever
    with nothing reading it, and paid an extra RSA encryption plus a
    file read on every auth reply for a field no minion would use.
    """
    import salt.master

    pki = tmp_path / "pki"
    (pki / "minions").mkdir(parents=True)
    opts = salt.config.DEFAULT_MASTER_OPTS.copy()
    opts.update({"pki_dir": str(pki), "transport": "zeromq", "id": "m"})
    opts["zmq_presence_subscriptions"] = False

    assert not salt.utils.channel.transport_provides_presence(opts)

    source = pathlib.Path(salt.master.__file__).read_text()
    assert "transport_provides_presence(self.opts)" in source, (
        "the auth reply assigns a topic without checking whether this "
        "master uses presence at all"
    )

    # And nothing created the secret as a side effect of asking.
    assert not os.path.exists(salt.utils.presence.presence_secret_path(opts))


def test_an_isolated_cluster_filesystem_is_warned_about(tmp_path, caplog):
    """
    ``presence_secret_path`` puts the secret in ``cluster_pki_dir``
    precisely so peers agree. With ``cluster_isolated_filesystem`` set
    they deliberately do not share that directory, and the cluster's
    state sync replicates only keys, denied_keys, file_roots and
    pillar_roots -- so each peer mints its own and a minion whose
    authentication and publish connections land on different peers
    cannot be named by the second.

    Not refused, because presence still works for every minion whose two
    connections land on the same peer; but an operator has to be told.
    """
    shared = tmp_path / "cluster_pki"
    shared.mkdir()
    opts = {
        "pki_dir": str(tmp_path),
        "cluster_pki_dir": str(shared),
        "cluster_isolated_filesystem": True,
    }
    salt.utils.presence._warned_at.clear()

    with caplog.at_level(logging.WARNING):
        salt.utils.presence.presence_secret_path(opts)

    assert (
        "cluster_isolated_filesystem" in caplog.text
    ), "a mode that silently breaks cross-peer naming produced no warning"
