"""
Tests for the presence record shared between the publish server and
everything that asks which minions are connected.

The central property is the one in the module docstring: an absent or stale
record must read as "no answer", never as "nobody is connected".  Callers
fall back to address matching on ``None``, so getting this wrong would report
a healthy fleet as entirely down -- a worse version of the bug the record
exists to fix, and one that reaches ``max_minions`` enforcement and
``ping_all_connected_minions`` rather than only reporting.
"""

import logging
import os
import pathlib
import stat
import time

import pytest

import salt.cache.localfs
import salt.utils.files
import salt.utils.msgpack
import salt.utils.presence
from tests.support.mock import patch

pytestmark = [
    pytest.mark.core_test,
]


@pytest.fixture
def opts(tmp_path):
    return {"cachedir": str(tmp_path), "id": "master-a"}


def _age(record_path, seconds):
    """Backdate a record's mtime-independent ``updated`` stamp."""
    with salt.utils.files.fopen(record_path, "rb") as fp_:
        record = salt.utils.msgpack.load(fp_, raw=False)
    record["updated"] -= seconds
    with salt.utils.files.fopen(record_path, "wb") as fp_:
        salt.utils.msgpack.dump(record, fp_)


def test_round_trip(opts):
    salt.utils.presence.write(
        opts, {"minion-one": "10.0.0.1", "minion-two": ""}, uptime=600.0
    )
    assert salt.utils.presence.read(opts) == {
        "minion-one": "10.0.0.1",
        "minion-two": "",
    }


def test_an_empty_answer_is_not_an_answer(opts):
    """
    An empty record is produced both by a master with nothing connected and
    by one whose subscribers it cannot name -- minions too old to announce
    themselves, or nameable only under a ``zmq_filtering`` they do not
    have.  Nothing distinguishes the two, and answering ``{}`` for the
    second reports a healthy fleet as entirely absent, through
    ``manage.present``, through ``ping_all_connected_minions`` targeting an
    empty list, and through ``max_minions``.

    Falling back gives up almost nothing: address matching on a genuinely
    empty fleet answers empty as well, so the only case surrendered is one
    where both mechanisms already agree.
    """
    salt.utils.presence.write(opts, {}, uptime=600.0)
    assert salt.utils.presence.read(opts) is None


def test_missing_record_is_no_answer(opts):
    assert salt.utils.presence.read(opts) is None


def test_stale_record_is_no_answer(opts):
    salt.utils.presence.write(opts, {"minion-one": ""}, uptime=600.0)
    assert salt.utils.presence.read(opts, stale_after=-1) is None


def test_record_within_the_window_is_used(opts):
    salt.utils.presence.write(opts, {"minion-one": ""}, uptime=600.0)
    assert salt.utils.presence.read(opts, stale_after=3600) == {"minion-one": ""}


def test_heartbeat_is_well_inside_the_stale_window(opts):
    """
    The writer refreshes every HEARTBEAT seconds; if that were not
    comfortably shorter than STALE_AFTER, an ordinary scheduling hiccup would
    read as a dead publish server and silently fall back.
    """
    assert salt.utils.presence.HEARTBEAT * 2 < salt.utils.presence.STALE_AFTER


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not msgpack at all",
        salt.utils.msgpack.dumps(["not", "a", "mapping"]),
        salt.utils.msgpack.dumps({"minions": {"m": ""}}),  # no timestamp
        salt.utils.msgpack.dumps({"updated": time.time()}),  # no minions
        salt.utils.msgpack.dumps({"updated": "soon", "minions": {}}),
    ],
)
def test_damaged_record_is_no_answer(opts, content):
    with open(salt.utils.presence.path(opts), "wb") as fp_:
        fp_.write(content)
    assert salt.utils.presence.read(opts) is None


def test_write_survives_a_cachedir_that_is_not_a_directory(tmp_path):
    """
    Presence is a nicety; failing to record it must not take down the publish
    server that was trying to.
    """
    not_a_dir = tmp_path / "cachedir"
    not_a_dir.write_text("")
    opts = {"cachedir": str(not_a_dir), "id": "master-a"}
    salt.utils.presence.write(opts, {"minion-one": ""}, uptime=600.0)
    assert salt.utils.presence.read(opts) is None


def test_write_survives_a_missing_cachedir(tmp_path):
    """
    Presence is a nicety; failing to record it must not take down the publish
    server that was trying to.
    """
    opts = {"cachedir": str(tmp_path / "does-not-exist")}
    salt.utils.presence.write(opts, {"minion-one": ""}, uptime=600.0)
    assert salt.utils.presence.read(opts) is None


@pytest.mark.skip_if_binaries_missing("id")
def test_write_survives_an_unwritable_cachedir(tmp_path):
    """
    As above, but for a cachedir that exists and cannot be written to --
    the case a missing directory does not actually exercise, since there
    ``read`` returns ``None`` from the open whatever ``write`` did.
    """
    cachedir = tmp_path / "locked"
    cachedir.mkdir()
    cachedir.chmod(0o500)
    try:
        if os.access(str(cachedir), os.W_OK):
            pytest.skip("running as a user that ignores directory permissions")
        opts = {"cachedir": str(cachedir), "id": "master-a"}
        salt.utils.presence.write(opts, {"minion-one": ""}, uptime=600.0)
        assert salt.utils.presence.read(opts) is None, "nothing should have landed"
        assert os.listdir(str(cachedir)) == [], "no temp file left behind either"
    finally:
        cachedir.chmod(0o700)


def test_record_is_not_the_maintenance_cache(opts):
    """
    ``Maintenance`` keeps its own polled presence cache in a different format.
    Exactly one of the two is written at a time, but a configuration change
    can leave the other behind, so they must not share a file.
    """
    assert not salt.utils.presence.path(opts).endswith("presence-data")


def test_master_ids_that_differ_only_in_unsafe_characters_do_not_collide(opts):
    """
    The master id is a configuration value, so it is slugged into a file
    name.  That is lossy, hence the digest alongside it.
    """
    first = dict(opts, id="master/one")
    second = dict(opts, id="master:one")
    assert salt.utils.presence.path(first) != salt.utils.presence.path(second)
    assert (
        os.path.dirname(salt.utils.presence.path(first)) == opts["cachedir"]
    ), "a master id with a separator in it must not escape the cachedir"


def test_an_unsettled_publish_server_is_no_answer(opts):
    """
    A publish server that just started has an empty connected set and fills
    it as subscribers reconnect.  That record is fresh, and fresh is exactly
    what stops a reader falling back -- so without this it would report the
    fleet it is still waiting for as gone.
    """
    # A *partial* fleet, not an empty one: an empty record is refused by a
    # different rule, so using one here would pass with the settle check
    # deleted and test nothing.
    salt.utils.presence.write(opts, {"first-one-back": ""}, uptime=0.0)
    assert salt.utils.presence.read(opts) is None

    salt.utils.presence.write(
        opts,
        {"minion-one": ""},
        uptime=salt.utils.presence.SETTLE_AFTER + 1,
    )
    assert salt.utils.presence.read(opts) == {"minion-one": ""}


def test_the_record_is_no_more_readable_than_the_cache_beside_it(opts):
    """
    The record names every connected minion and the address it is
    connected from, which is no less sensitive than the grains next to it.

    Compared against a file actually written by ``salt.cache.localfs``,
    not against this module's own expression for the mode -- an earlier
    version of this test rebuilt the reference with the same formula the
    implementation used, so it was a tautology and it let the record sit
    at 0644 next to a 0600 cache without complaint.
    """
    salt.cache.localfs.store(
        bank="minions/some-minion",
        key="data",
        data={"grains": {}},
        cachedir=opts["cachedir"],
    )
    reference = os.path.join(opts["cachedir"], "minions", "some-minion", "data.p")
    salt.utils.presence.write(opts, {"minion-one": "10.0.0.1"}, uptime=600.0)

    record_mode = stat.S_IMODE(os.stat(salt.utils.presence.path(opts)).st_mode)
    cache_mode = stat.S_IMODE(os.stat(reference).st_mode)

    assert record_mode & ~cache_mode == 0, (
        f"the record ({record_mode:o}) grants access the minion cache"
        f" ({cache_mode:o}) does not"
    )


def _raw_write(opts, record):
    """Write a record verbatim, bypassing ``write``'s own stamping.

    A live ``pid`` is filled in unless the record names one, so that a
    test about some *other* field is not silently answered by the
    dead-writer rule instead. Tests about that rule set it explicitly.
    """
    record = dict(record)
    record.setdefault("pid", os.getpid())
    with salt.utils.files.fopen(salt.utils.presence.path(opts), "wb") as fp_:
        salt.utils.msgpack.dump(record, fp_)


def test_a_record_that_is_never_refreshed_never_becomes_authoritative(opts):
    """
    The publish daemon writes one record at startup, before its heartbeat
    has run even once.  Until something refreshes it that record stays
    unsettled however long it sits there, because the settle window is
    measured from the writer's own clock rather than the reader's: an
    empty connected set that nothing has yet vouched for must never read
    as "nobody is connected".
    """
    born = time.time() - (salt.utils.presence.STALE_AFTER / 2)
    # A NON-empty roster on purpose: an empty one is refused by a
    # different rule, so using one here would pass with the settle check
    # deleted and test nothing. The sibling test above says so, and this
    # one used to make exactly that mistake.
    _raw_write(
        dict(opts, id="master-a"),
        {"updated": born, "uptime": 0.0, "minions": {"minion-one": ""}},
    )

    assert salt.utils.presence.read(opts) is None

    # A heartbeat settles it, but an empty answer still is not one -- see
    # test_an_empty_answer_is_not_an_answer.
    _raw_write(
        dict(opts, id="master-a"),
        {"updated": time.time(), "uptime": 600.0, "minions": {}},
    )
    assert salt.utils.presence.read(opts) is None

    # With somebody in it, the settled record is used.
    _raw_write(
        dict(opts, id="master-a"),
        {"updated": time.time(), "uptime": 600.0, "minions": {"minion-one": ""}},
    )
    assert salt.utils.presence.read(opts) == {"minion-one": ""}


def test_the_first_warning_is_not_swallowed_on_a_freshly_booted_host(opts, caplog):
    """
    The throttle is keyed on ``time.monotonic``, which is measured from boot.
    Seeded at zero it would eat every warning for the first
    ``_WARN_INTERVAL`` of the host's uptime -- which is when a master is most
    likely to have something worth saying.  Monotonic is pinned low here
    because on a host that has been up for a while the bug hides itself.
    """
    salt.utils.presence._warned_at.clear()
    salt.utils.presence.write(opts, {"minion-one": ""}, uptime=600.0)
    _age(salt.utils.presence.path(opts), salt.utils.presence.STALE_AFTER + 10)

    with patch("time.monotonic", return_value=5.0):
        with caplog.at_level(logging.WARNING):
            assert salt.utils.presence.read(opts) is None
    assert [
        r for r in caplog.records if "seconds old" in r.message
    ], "the first stale warning must survive a host that booted moments ago"


def test_the_warning_throttle_still_holds(opts, caplog):
    """
    ``read`` runs once per authentication among other things, and every
    condition it warns about is persistent, so one problem must not become a
    log flood.
    """
    salt.utils.presence._warned_at.clear()
    salt.utils.presence.write(opts, {"minion-one": ""}, uptime=600.0)
    _age(salt.utils.presence.path(opts), salt.utils.presence.STALE_AFTER + 10)

    with patch("time.monotonic", return_value=5.0):
        with caplog.at_level(logging.WARNING):
            for _ in range(5):
                salt.utils.presence.read(opts)
    assert len([r for r in caplog.records if "seconds old" in r.message]) == 1


def test_the_record_is_not_world_writable(opts):
    """
    Anyone who could write it could forge the connected set -- inflating the
    count ``max_minions`` is enforced against until authentication is locked
    out, or hiding minions from ``connected_ids()`` entirely.
    """
    salt.utils.presence.write(opts, {"minion-one": ""}, uptime=600.0)
    mode = stat.S_IMODE(os.stat(salt.utils.presence.path(opts)).st_mode)

    assert not mode & stat.S_IWOTH, "the presence record must not be world-writable"
    assert not mode & stat.S_IWGRP, "nor group-writable"


def test_a_failed_write_leaves_no_temp_file_behind(opts):
    """
    ENOSPC mid-write, or a failing rename, would otherwise leak one file per
    heartbeat -- 2880 a day -- into the cachedir.
    """
    with patch(
        "salt.utils.atomicfile.atomic_rename", side_effect=OSError("no space left")
    ):
        salt.utils.presence.write(opts, {"minion-one": ""}, uptime=600.0)

    assert os.listdir(opts["cachedir"]) == [], "a temp file was left behind"


def test_a_record_without_an_uptime_is_no_answer(opts):
    """
    ``uptime`` decides whether the record is settled, and the comparison
    subtracts from it. A record lacking one -- an older writer, a
    truncated file -- would raise ``TypeError`` out of ``read()`` and into
    whatever asked, which includes the authentication path, once per
    authentication.
    """
    _raw_write(
        dict(opts, id="master-a"),
        {"updated": time.time(), "minions": {"minion-one": ""}},
    )

    assert salt.utils.presence.read(opts) is None


def test_a_record_with_a_non_numeric_uptime_is_no_answer(opts):
    """
    Same comparison, same consequence.
    """
    _raw_write(
        dict(opts, id="master-a"),
        {
            "updated": time.time(),
            "uptime": "soon",
            "minions": {"minion-one": ""},
        },
    )

    assert salt.utils.presence.read(opts) is None


def test_a_record_dated_in_the_future_is_not_usable(opts):
    """
    A backward clock step -- a VM resumed from a snapshot, chrony stepping
    after an outage -- stamps everything written before it into the
    reader's future. An age that is only ever compared against an upper
    bound then never expires, so a frozen roster stays authoritative for
    as long as the step lasts, including after the publish daemon that
    wrote it has died -- which is the state the writer-liveness check and
    the staleness rule both exist to get out of, and which a clock in the
    future would otherwise defeat for the staleness half.
    """
    _raw_write(
        dict(opts, id="master-a"),
        {
            "updated": time.time() + 3600,
            "uptime": 600.0,
            "minions": {"ghost-minion": "10.0.0.1"},
        },
    )

    assert salt.utils.presence.read(opts) is None


def test_a_little_clock_jitter_is_tolerated(opts):
    """
    Writer and reader are the same host, but not the same instant; a
    sub-second overshoot must not throw the answer away.
    """
    _raw_write(
        dict(opts, id="master-a"),
        {
            "updated": time.time() + 0.5,
            "uptime": 600.0,
            "minions": {"minion-one": ""},
        },
    )

    assert salt.utils.presence.read(opts) == {"minion-one": ""}


def test_a_negative_uptime_is_not_a_settled_record(opts):
    """
    ``uptime`` is monotonic at the writer, so a negative value means the
    record is damaged rather than old. It reads as unsettled -- which is
    the same route an ordinary too-young record takes, deliberately: both
    end at "no answer", and there is nothing a damaged record should be
    trusted for that a young one should not.
    """
    _raw_write(
        dict(opts, id="master-a"),
        {
            "updated": time.time(),
            "uptime": -60.0,
            "minions": {"only-one-back-so-far": ""},
        },
    )

    assert salt.utils.presence.read(opts) is None


def test_a_record_whose_values_are_not_addresses_is_no_answer(opts):
    """
    ``connected_ids`` builds a set of ``(id, address)`` pairs from these,
    so an unhashable value raises out of ``read`` and into the
    authentication path, once per authentication.
    """
    _raw_write(
        dict(opts, id="master-a"),
        {
            "updated": time.time(),
            "uptime": 600.0,
            "since": 0.0,
            "minions": {"m1": ["10.0.0.1"], "m2": "ok"},
        },
    )
    assert salt.utils.presence.read(opts) is None


def test_the_windows_are_sane_absolutely_not_just_relatively():
    """
    Every other test ages records by ``STALE_AFTER + 10``, so the suite
    scales with whatever these happen to be: a ``STALE_AFTER`` of a year
    would keep the whole suite green while making a record left by a
    daemon that died months ago authoritative.
    """
    assert 10 <= salt.utils.presence.HEARTBEAT <= 120
    assert salt.utils.presence.HEARTBEAT * 2 < salt.utils.presence.STALE_AFTER <= 600
    assert 10 <= salt.utils.presence.SETTLE_AFTER <= 300


def test_peers_sharing_a_cachedir_do_not_overwrite_each_other(opts):
    """
    The per-master filename is the one thing kept from the cluster work.
    Peers on a shared ``cachedir`` each write their own record and each
    reads its own: a master answers for the minions connected to it, which
    is the scope address matching always had.

    Salt's own ``<cachedir>/presence-data`` has the opposite behaviour --
    every peer's ``Maintenance`` writes that one path -- so this also
    avoids inheriting that clobber.
    """
    peer_a = dict(opts, id="master-a")
    peer_b = dict(opts, id="master-b")
    salt.utils.presence.write(peer_a, {"minion-one": "10.0.0.1"}, uptime=600.0)
    salt.utils.presence.write(peer_b, {"minion-two": "10.0.0.2"}, uptime=600.0)

    assert salt.utils.presence.path(peer_a) != salt.utils.presence.path(peer_b)
    assert salt.utils.presence.read(peer_a) == {"minion-one": "10.0.0.1"}
    assert salt.utils.presence.read(peer_b) == {"minion-two": "10.0.0.2"}


def test_a_peers_record_is_never_read_in_place_of_our_own(opts):
    """
    A master with no record of its own must fall back, not borrow a
    neighbour's answer -- that would report minions connected to some
    other master as connected to this one.
    """
    salt.utils.presence.write(dict(opts, id="master-b"), {"theirs": ""}, uptime=600.0)

    assert salt.utils.presence.read(dict(opts, id="master-a")) is None


def test_a_record_whose_minions_are_not_a_mapping_is_no_answer(opts):
    """
    ``minions`` is iterated as a mapping by ``connected_ids``. A list
    there raises ``AttributeError`` from ``minions.items()`` -- outside
    ``_read_one``'s try block, so out of ``read()``, out of
    ``connected_ids()`` and into the authentication path, once per
    authentication.

    The sibling guard on the *values* has a test; this one on the
    container did not, and no parametrised damaged record reached it --
    they were all rejected earlier for a missing ``updated`` or
    ``uptime``.
    """
    _raw_write(
        dict(opts, id="master-a"),
        {"updated": time.time(), "uptime": 600.0, "minions": ["minion-one"]},
    )

    assert salt.utils.presence.read(opts) is None


def _dead_pid():
    """A pid that is certainly not running.

    Claimed by forking a child and reaping it, so the number really did
    belong to a process and really is gone -- rather than picking a large
    integer and hoping.
    """
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child never returns
        os._exit(0)
    os.waitpid(pid, 0)
    return pid


def test_a_record_from_a_dead_publish_server_is_no_answer(opts):
    """
    ``manage.present`` reads the cachedir and needs no running master, so
    a record left behind by one that has stopped -- or been OOM-killed,
    or crashed -- goes on naming its whole last-known fleet until it ages
    out two minutes later. Before this module existed the answer in that
    situation was an empty socket table, which was correct.

    A shutdown hook cannot cover this: SIGKILL, an OOM kill and a crash
    all skip it, and those are exactly when a roster gets left behind.
    """
    _raw_write(
        dict(opts, id="master-a"),
        {
            "updated": time.time(),
            "uptime": 600.0,
            "minions": {"minion-one": ""},
            "pid": _dead_pid(),
        },
    )

    assert salt.utils.presence.read(opts) is None


def test_a_record_from_a_live_publish_server_is_an_answer(opts):
    """
    The other half: the liveness probe must not reject a healthy record,
    or presence never works at all.
    """
    salt.utils.presence.write(opts, {"minion-one": "10.0.0.1"}, uptime=600.0)

    assert salt.utils.presence.read(opts) == {"minion-one": "10.0.0.1"}


def test_a_record_without_a_writer_is_no_answer(opts):
    """
    Nothing this branch ships writes a record without a ``pid``, so one
    that lacks it was written by something unknown. Refusing it costs a
    fallback; trusting it means trusting a roster with no way to tell
    whether anybody still maintains it.
    """
    _raw_write(
        dict(opts, id="master-a"),
        {
            "updated": time.time(),
            "uptime": 600.0,
            "minions": {"minion-one": ""},
            "pid": None,
        },
    )

    assert salt.utils.presence.read(opts) is None


@pytest.mark.parametrize(
    "error,alive,why",
    [
        (ProcessLookupError(), False, "ESRCH is the only proof of death"),
        (
            PermissionError(),
            True,
            "EPERM means the process exists and belongs to someone else -- "
            "a master running as root read by a non-root salt-run, which is "
            "an ordinary deployment and must not read as 'dead'",
        ),
        (
            OSError(),
            True,
            "an unclassifiable error is not evidence of death; staleness "
            "still bounds how long trusting it can matter",
        ),
    ],
)
def test_what_the_liveness_probe_makes_of_each_errno(error, alive, why):
    """
    The three outcomes of ``os.kill(pid, 0)``. Only the first is
    reachable in a test that owns its own processes, so the other two are
    driven directly -- getting EPERM wrong would make presence collapse
    to address matching on every deployment where the reader is not the
    master's user.
    """
    with patch("os.kill", side_effect=error):
        assert salt.utils.presence._writer_is_alive(os.getpid()) is alive, why


def test_a_corrupt_pid_does_not_escape_into_the_authentication_path(opts):
    """
    ``os.kill`` raises ``OverflowError`` -- not ``OSError`` -- for a pid
    too large for ``pid_t``. Uncaught, a single corrupt integer in the
    record comes out of ``connected_ids()`` into ``max_minions``
    enforcement once per authentication, and stays there until somebody
    deletes the file by hand. This is the same failure the value guard
    above it was added for; ``pid`` was simply left out of it.
    """
    _raw_write(
        dict(opts, id="master-a"),
        {
            "updated": time.time(),
            "uptime": 600.0,
            "minions": {"minion-one": ""},
            "pid": 2**63,
        },
    )

    assert salt.utils.presence.read(opts) is None


@pytest.mark.parametrize("pid", [True, 0, -1, "1", 1.5, None])
def test_an_implausible_pid_is_not_alive(pid):
    """
    Each of these would otherwise read as "the writer is running":
    ``True`` is ``1`` and signals init, ``0`` signals the reader's own
    process group, ``-1`` signals everything it may signal. Any of them
    makes a stale or forged roster authoritative for its whole staleness
    window.
    """
    assert salt.utils.presence._writer_is_alive(pid) is False


def test_an_empty_secret_file_is_replaced(tmp_path):
    """
    ``os.open`` can succeed and ``os.write`` then fail -- ENOSPC, EIO, or
    the process dying in between -- leaving a zero-byte file. Without
    this, every later call falls through to the exclusive create, which
    fails because the file exists, and the handler re-reads the same
    empty file: ``topic_for`` returns None forever, no minion is ever
    assigned a topic, and the master silently reverts to address
    matching. Only deleting the file by hand would recover.
    """
    opts = {"pki_dir": str(tmp_path)}
    path = salt.utils.presence.presence_secret_path(opts)
    pathlib.Path(path).write_bytes(b"")

    secret = salt.utils.presence.presence_secret(opts)

    assert secret, "an empty secret file was treated as authoritative"
    assert salt.utils.presence.presence_secret(opts) == secret
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_a_failed_write_leaves_no_empty_secret_behind(tmp_path):
    """
    The other half: the zero-byte file must not be created in the first
    place. A disk that fills during the write is the realistic producer.
    """
    opts = {"pki_dir": str(tmp_path)}
    path = salt.utils.presence.presence_secret_path(opts)

    with patch("os.write", side_effect=OSError(28, "No space left on device")):
        salt.utils.presence.presence_secret(opts)

    assert not os.path.exists(
        path
    ), "a zero-byte secret was left behind; presence would never recover"

    assert salt.utils.presence.presence_secret(opts), "and it must recover now"


def test_the_record_carries_the_writing_process_pid(opts):
    """
    The dead-writer rule is what stops a SIGKILLed or OOM-killed publish
    daemon's roster being believed for the rest of its staleness window
    -- ``test_a_clean_shutdown_takes_the_record_with_it`` explicitly
    defers to it. But every test of that rule goes through ``_raw_write``
    with a pid chosen by the test, so ``write`` itself could stamp
    ``os.getppid()``, a value captured before a fork, or a constant, and
    ship green with the rule inert.

    Written by a real child process which is then reaped, so the pid in
    the record is genuinely dead by the time it is read.
    """
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child never returns
        try:
            salt.utils.presence.write(opts, {"minion-one": "10.0.0.1"}, 600.0)
        finally:
            os._exit(0)
    os.waitpid(pid, 0)

    assert os.path.exists(salt.utils.presence.path(opts)), "the child wrote nothing"
    assert salt.utils.presence.read(opts) is None, (
        "a record written by a process that has since died is still "
        "believed; a killed publish daemon goes on naming its whole "
        "last-known fleet"
    )


def test_a_non_numeric_updated_is_no_answer(opts):
    """
    ``updated`` is subtracted from, so a string there raises TypeError
    out of ``read()`` and into the authentication path.

    The parametrised damaged-record case meant to cover this has no
    ``uptime`` and no ``pid``, so two *other* rules reject it first and
    the guard itself is never reached -- the same "a different rule
    already rejects it" pattern that has hidden several of these.
    """
    _raw_write(
        dict(opts, id="master-a"),
        {
            "updated": "soon",
            "uptime": 600.0,
            "minions": {"minion-one": ""},
        },
    )

    assert salt.utils.presence.read(opts) is None


def test_the_warning_throttle_is_per_reason(opts, caplog):
    """
    Each rejection reason throttles separately. Collapsing them onto one
    key means the first stale record silences the malformed-record
    warning for five minutes, which is how a corrupt file goes unnoticed.
    """
    salt.utils.presence._warned_at.clear()
    with caplog.at_level(logging.WARNING):
        salt.utils.presence._warn("stale", "record is stale")
        salt.utils.presence._warn("malformed", "record is malformed")

    assert "record is stale" in caplog.text
    assert (
        "record is malformed" in caplog.text
    ), "a second reason was swallowed by the first reason's throttle"
