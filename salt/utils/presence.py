"""
A snapshot of which minions are connected to the publish server.

The publish server knows exactly which minion is behind each connection: the
tcp transport authenticates it, and the zeromq transport reads it out of the
subscription topic (see
``salt.transport.zeromq.PublishServer._subscription_presence``). That
knowledge lives in the publish daemon process, while almost everything that
asks "which minions are connected" -- the ``manage`` runners, ``max_minions``
enforcement at auth time, ``ping_all_connected_minions`` -- runs in some other
process. This module is the hand-off: the publish server writes a snapshot,
other processes read it.

The snapshot is deliberately treated as perishable. ``read`` returns ``None``
rather than an empty mapping when the record is missing, unreadable, stale or
not yet settled, so a caller falls back to whatever it did before instead of
concluding that every minion is gone. Reporting a live fleet as absent is the
failure this whole mechanism exists to fix, and a publish daemon that died,
a record that was never written, or one written seconds after a restart that
the fleet has not finished reconnecting to must not reintroduce it.

Who can read it
---------------

A record is written owner-only, matching the minion data cache beside it:
``salt.cache.localfs`` writes through ``mkstemp`` and never widens the
mode, so ``<cachedir>/minions/<id>/data.p`` is 0600 too. Both halves of
the answer are therefore reachable by exactly the same callers -- a user
who can read one can read the other, and a user who can read neither gets
nothing from either rather than a different answer from each.

The exception is an external ``cache`` backend (redis, consul, etcd,
mysql): the fallback then needs no ``cachedir`` at all and will answer
where this does not.

One record per publish server, not one per master
-------------------------------------------------

A cluster master's ``cachedir`` may be shared between its peers (see
:ref:`tutorial-master-cluster`), so the record is named after the master
that wrote it. That is only to stop peers overwriting each other -- the
records are not combined.

Each master answers for the minions connected to *it*, which is the scope
address matching always had: a peer's socket table never held another
peer's connections, and nothing in Salt merges presence across a cluster.
``manage.present`` on one peer reports that peer's share, as it did before.
Deliberately so -- making the answer cluster-wide means deciding whether a
silent peer is empty or merely absent, and that question has no safe answer
from a shared directory.
"""

import binascii
import hashlib
import hmac
import logging
import os
import re
import tempfile
import time

import salt.utils.atomicfile
import salt.utils.files
import salt.utils.stringutils
import salt.utils.msgpack

log = logging.getLogger(__name__)

#: Rewrite the record at least this often even when nothing changes, so that
#: its age means "the publish server is alive and this is current" rather than
#: "nothing has happened recently".
#:
#: The heartbeat starts with the publish server, not with its first
#: *change*, because the case that needs it is a master that is quiet but
#: populated: a settled fleet with nobody arriving or leaving produces no
#: changes at all, and without a refresh its record would age past
#: ``STALE_AFTER`` and drop every one of those minions back to address
#: matching -- which is the NAT bug this exists to fix, arriving two
#: minutes after things went quiet.
#:
#: Note it does nothing for a publish server with *nobody* connected: an
#: empty roster is refused by ``read`` however fresh it is, so refreshing
#: one changes no answer.
HEARTBEAT = 30.0

#: Ignore a record older than this. Comfortably more than ``HEARTBEAT`` so an
#: ordinary scheduling hiccup does not look like a dead publish server.
STALE_AFTER = 120.0

#: Ignore every record a publish server wrote within this long of starting.
#: A publish server starts with an empty connected set and fills it as
#: subscribers reconnect, which takes as long as their randomised 0MQ
#: reconnect interval plus backoff. Until then the record is fresh but
#: incomplete, and "fresh" is exactly what stops a reader falling back -- so a
#: restarted publish daemon would report the fleet it is still waiting for as
#: gone. Treating that window as "no answer" is the lesser harm, not a free
#: one: the fallback is what the caller did before this module existed, and
#: on the NAT'd fleet this exists for that answer is "nobody is connected".
#: Bounded at ``SETTLE_AFTER`` that is a fair trade. Anything that makes the
#: fallback *unbounded* is not, which is why the rules below are written
#: to fail towards an answer rather than towards silence.
#:
#: Measured on the writer's own monotonic clock, so it is a
#: property of the record rather than of when it happens to be read.
SETTLE_AFTER = 30.0

#: How far into the reader's future a record may be stamped before it is
#: treated as unusable rather than merely fresh. Writer and reader are the
#: same host, so this only has to absorb scheduling jitter.
_CLOCK_TOLERANCE = 5.0

#: Records are ``PREFIX + <slug>-<digest>.p`` in ``cachedir``, where the two
#: halves together name the writing master; see ``_record_name``. Not
#: ``presence-data``,
#: which is ``Maintenance``'s own polled cache in a different format: only one
#: of the two is ever being written, but they can outlive a configuration
#: change, so they do not share a name.
PREFIX = "subscription-presence-"
SUFFIX = ".p"

#: Throttle for this module's warnings. ``read`` is called once per
#: authentication among other things, and every condition it warns about is
#: persistent -- a publish server that stopped updating its record stays
#: stopped, an unreadable record stays unreadable -- so warning per call would
#: turn one problem into a log flood.
_WARN_INTERVAL = 300.0

#: Last time each warning fired, keyed by call site. Seeded below zero rather
#: than at zero: ``time.monotonic`` is measured from boot on Linux, so a plain
#: zero would swallow every warning for the first ``_WARN_INTERVAL`` of the
#: host's uptime -- which is exactly when a master is most likely to have
#: something worth saying.
_warned_at = {}

#: ``_read_one`` saying "this writer is alive but not caught up yet", which is
#: not the same as having nothing to say.
_UNSETTLED = object()


def _record_name(opts):
    """File name for this master's own record.

    The master id is a configuration value, so it is reduced to characters
    that are unambiguously safe in a file name. That is lossy, hence the
    digest of the real id alongside it: two masters whose ids differ only in
    the stripped characters must not share a record.
    """
    master_id = str(opts.get("id") or "master")
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", master_id)[:64]
    digest = hashlib.sha1(master_id.encode()).hexdigest()[:8]
    return f"{PREFIX}{slug}-{digest}{SUFFIX}"


def path(opts):
    """Where this master's own snapshot lives."""
    return os.path.join(opts["cachedir"], _record_name(opts))


def _write_atomic(record_path, payload):
    """Replace ``record_path`` with ``payload``, atomically and without fsync.

    Deliberately not :func:`salt.utils.atomicfile.atomic_open`, which fsyncs
    before the rename. There is nothing here worth making durable -- the
    record is rewritten at least every ``HEARTBEAT`` seconds and a reader that
    finds it missing falls back rather than trusting it -- and the write runs
    on the publish daemon's ioloop, the same loop that sends every published
    job. A cluster's ``cachedir`` is often a network filesystem, where that
    fsync is exactly the kind of stall that must not land there.

    The mode matches the minion data cache beside it -- owner-only -- so
    the record is no more readable than the grains it replaces as the
    source of truth. It is re-applied on every write, so hardening it
    further by hand will not survive the next heartbeat.
    """
    fd, tmp = tempfile.mkstemp(prefix=f".{PREFIX}", dir=os.path.dirname(record_path))
    try:
        with os.fdopen(fd, "wb") as fp_:
            fp_.write(payload)
        # 0600, matching what the minion data cache beside it actually
        # gets: ``salt.cache.localfs`` writes through ``mkstemp``, which is
        # owner-only, and never chmods. An earlier version of this used
        # ``atomicfile``'s new-file mode (0o666 & ~umask, so usually 0644)
        # on the theory that it matched the rest of the cache. It does not,
        # and the difference is not cosmetic: the record names every
        # connected minion and the address it is connected from, which is
        # no less sensitive than the grains next to it.
        os.chmod(tmp, 0o600)
        # salt.utils.atomicfile rather than os.replace: on Windows a rename
        # over a file another process holds open fails, and a reader holds
        # this one open on every authentication. atomic_rename is os.rename
        # on POSIX and a transacted move with retries on Windows.
        salt.utils.atomicfile.atomic_rename(tmp, record_path)
    except Exception:  # pylint: disable=broad-except
        # Broad on purpose. The cleanup has to happen whatever went wrong,
        # and not every failure here is an OSError: ``atomic_rename``'s
        # last-resort branch on Windows references a Python 2 name and
        # raises ``AttributeError``. Leaking a temp file per write would
        # fill the cachedir at one file a second.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write(opts, minions, uptime):
    """Record the currently connected minions.

    ``minions`` maps minion id to the address it is connected from, which may
    be an empty string when the transport cannot report one.

    ``uptime`` is how long this publish server has been running, measured
    on its own monotonic clock, so readers can tell a settled record from
    one that is merely fresh; see ``SETTLE_AFTER``. It is required: a
    record without a usable one is rejected as malformed by ``_read_one``,
    so there is no "take it at face value" reading to offer.
    """
    record = {
        "updated": time.time(),
        "uptime": uptime,
        "minions": dict(minions),
        # Who wrote it. A record is only worth anything while the publish
        # server that maintains it is still running, and nothing else can
        # establish that: a shutdown hook covers a clean stop and nothing
        # else, where a crash, an OOM kill or a SIGKILL are exactly when a
        # roster is most likely to be left behind. See ``_writer_is_alive``.
        "pid": os.getpid(),
    }
    try:
        _write_atomic(path(opts), salt.utils.msgpack.dumps(record))
    except OSError as exc:
        _warn("write", "Unable to write the presence record: %s", exc)


def _writer_is_alive(pid):
    """Whether the process that wrote a record still exists.

    Writer and reader are the same host -- a master reads only the record
    it wrote itself -- so this is a local pid and a plain signal-0 probe
    answers it.

    ``EPERM`` means the process exists and belongs to somebody else,
    which is still alive. Only ``ESRCH`` is proof of death.

    Pid reuse inside the ``STALE_AFTER`` window would make a dead writer
    look alive; that merely returns the behaviour to what it was without
    this check, and the staleness rule still bounds it.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OverflowError:
        # A pid too large for ``pid_t``. ``os.kill`` raises this rather
        # than OSError, and it is not caught below -- so a single corrupt
        # integer in the record would escape ``read`` and come out of
        # ``connected_ids`` into the authentication path, once per
        # authentication, until somebody deleted the file by hand.
        return False
    except PermissionError:
        return True
    except OSError:
        # Cannot tell. Err towards trusting the record; staleness still
        # bounds how long that can matter.
        return True
    return True


def remove(opts):
    """Delete this master's record, if it has one.

    Called when a publish server starts up on a transport that does not
    report presence. The previous incarnation's roster is otherwise left
    on disk, still inside its ``STALE_AFTER`` and so still authoritative,
    naming minions that are not connected to this daemon at all. Turning
    the option off should fail to address matching at once, not after a
    window in which the master acts on a fleet that has gone.
    """
    record_path = path(opts)
    try:
        os.unlink(record_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        _warn("remove", "Unable to remove the presence record: %s", exc)


def _warn(key, message, *args):
    """Log ``message`` at most once per ``_WARN_INTERVAL`` per ``key``."""
    now = time.monotonic()
    if now - _warned_at.get(key, -_WARN_INTERVAL) < _WARN_INTERVAL:
        return
    _warned_at[key] = now
    log.warning(message, *args)


def _read_one(record_path, stale_after):
    """Load one record.

    Returns the record, ``_UNSETTLED`` if its publish server is still
    filling up, or ``None`` if there is nothing usable in it.
    """
    try:
        with salt.utils.files.fopen(record_path, "rb") as fp_:
            record = salt.utils.msgpack.load(fp_, raw=False)
    except FileNotFoundError:
        # Raced with the writer's rename, or with a record being cleaned up.
        return None
    except OSError as exc:
        _warn("read", "Unable to read the presence record %s: %s", record_path, exc)
        return None
    except Exception as exc:  # pylint: disable=broad-except
        _warn("unreadable", "Presence record %s is unreadable: %s", record_path, exc)
        return None

    if not isinstance(record, dict):
        _warn("mapping", "Presence record %s is not a mapping, ignoring", record_path)
        return None
    minions = record.get("minions")
    updated = record.get("updated")
    uptime = record.get("uptime")
    if (
        not isinstance(minions, dict)
        or not isinstance(updated, (int, float))
        or not isinstance(uptime, (int, float))
        or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in minions.items()
        )
    ):
        # The values matter as much as the shape: ``connected_ids`` builds
        # a set of ``(id, address)`` pairs out of them, so an unhashable
        # value raises out of here and into the authentication path, once
        # per authentication.
        _warn("malformed", "Presence record %s is malformed, ignoring", record_path)
        return None

    if not _writer_is_alive(record.get("pid")):
        # The publish server that maintains this is gone -- stopped,
        # killed or crashed -- so the roster is frozen at whatever was
        # true when it died, and it stays inside ``stale_after`` for up
        # to two minutes afterwards. Without this, a stopped master goes
        # on naming its whole last-known fleet to ``manage.present`` and
        # to anything else reading the cachedir, none of which needs the
        # master to be running. Before this module existed the answer in
        # that situation was an empty socket table, i.e. correct.
        _warn(
            "dead",
            "Presence record %s was written by a process that is no longer"
            " running, ignoring it and falling back to address matching",
            record_path,
        )
        return None

    now = time.time()
    age = now - updated
    if age > stale_after or age < -_CLOCK_TOLERANCE:
        # Bounded in both directions. A record dated in the future never
        # ages out, so a backward clock step -- a VM resumed from a
        # snapshot, chrony stepping after an outage, hwclock from a dead
        # RTC -- would otherwise pin a frozen roster as authoritative for
        # as long as the step, including after the publish daemon that
        # wrote it has died. Writer and reader are the same host, so
        # anything beyond scheduling jitter is a broken clock, not skew.
        #
        # In the forward direction: the publish server stopped updating
        # this -- it died, or presence was turned off and the file was
        # left behind. Either way we no longer know who is connected,
        # which is not the same as knowing nobody is.
        _warn(
            "stale",
            "Presence record %s is %d seconds old, ignoring it and falling"
            " back to address matching",
            record_path,
            age,
        )
        return None
    # Staleness is the one comparison here that crosses clocks at all:
    # ``updated`` is the writer's and ``now`` is this reader's. They are
    # the same host -- this master reads only the record this master
    # wrote -- so it is exposed to a step on that host's own clock and
    # not to skew between machines, and it fails to the fallback rather
    # than to a wrong answer.
    #
    # The settle check below crosses no clocks at all: it uses the
    # writer's own uptime at the moment it wrote this, a single
    # monotonic measurement, rather than any difference between two
    # stamps.
    #
    # A record written once and never refreshed reads as unsettled rather
    # than settled -- for the first ``STALE_AFTER``, after which the check
    # above has already skipped it as stale. Both readings decline to
    # trust it, which is the point. They end at the same place too:
    # ``read`` maps both to ``None``, so the sentinel survives only to
    # keep the two reasons distinguishable in the log.
    if uptime < SETTLE_AFTER:
        log.debug(
            "Presence record %s was written %d seconds into its publish"
            " server's life and may not have the whole fleet back yet",
            record_path,
            uptime,
        )
        return _UNSETTLED
    return record


def read(opts, stale_after=None):
    """Return ``{minion_id: address}``, or ``None`` if there is no usable answer.

    ``stale_after`` is a testing seam: production has one answer for how
    old is too old and it is ``STALE_AFTER``.

    ``None`` means "no answer", not "nobody is connected", and callers must
    treat it that way -- fall back to their own detection rather than report
    an empty fleet. It is returned when no record exists, when the record is
    unreadable, malformed or stale, when the publish server that wrote it is
    too recently started to have the fleet back, and when the answer would
    be empty (see below).

    This reads only *this* master's record. A master answers for the minions
    connected to it, which is exactly the scope address matching had: a
    cluster peer's socket table never contained another peer's connections
    either, and nothing in Salt has ever merged presence across peers. The
    per-master filename exists so peers sharing a ``cachedir`` do not
    overwrite each other -- not so that their records can be combined.
    """
    if stale_after is None:
        # Resolved per call rather than as a default argument so the module
        # constant stays the single source of truth.
        stale_after = STALE_AFTER

    record = _read_one(path(opts), stale_after)
    if record is None or record is _UNSETTLED:
        return None

    minions = record["minions"]
    if not minions:
        # "Nobody is connected" and "I could not name anybody" produce the
        # same empty record, and the difference matters enormously: the
        # second is a master whose minions are all too old to announce
        # themselves. Answering ``{}`` there reports
        # an entire healthy fleet as absent -- through ``manage.present``,
        # through ``ping_all_connected_minions``, which then targets an
        # empty list, and through ``max_minions``.
        #
        # Nothing here can tell the two apart. libzmq collapses the empty
        # delivery topic every subscriber shares into a single event, so the
        # unnameable ones cannot even be counted. Falling back costs almost
        # nothing: address matching on a genuinely empty fleet returns an
        # empty set too, so the only case this gives up is one where both
        # answers already agree.
        return None
    return dict(minions)
