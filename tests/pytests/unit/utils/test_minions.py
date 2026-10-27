import pytest

import salt.config
import salt.utils.minions
import salt.utils.network
import salt.utils.presence
from tests.support.mock import patch


def test_connected_ids():
    """
    test ckminion connected_ids when
    local_port_tcp returns 127.0.0.1
    """
    opts = salt.config.minion_config(None)
    opts.update(
        {
            "publish_port": 4505,
            "detect_remote_minions": False,
            "minion_data_cache": True,
            "__role": "minion",
        }
    )
    minion = "minion"
    ips = {"203.0.113.1", "203.0.113.2", "127.0.0.1"}
    mdata = {"ipv4": ips, "ipv6": []}
    patch_net = patch("salt.utils.network.local_port_tcp", return_value=ips)
    patch_list = patch("salt.cache.Cache.list", return_value=[minion])
    patch_fetch = patch("salt.cache.Cache.fetch", return_value=mdata)
    ckminions = salt.utils.minions.CkMinions(opts)
    with patch_net, patch_list, patch_fetch:
        ret = ckminions.connected_ids()
        assert ret == {minion}


def test_connected_ids_remote_minions():
    """
    test ckminion connected_ids when
    detect_remote_minions is set
    """
    opts = salt.config.minion_config(None)
    opts.update(
        {
            "publish_port": 4505,
            "detect_remote_minions": True,
            "remote_minions_port": 22,
            "minion_data_cache": True,
            "__role": "master",
        }
    )
    minion = "minion"
    minion2 = "minion2"
    minion2_ip = "192.168.2.10"
    minion_ips = {"203.0.113.1", "203.0.113.2", "127.0.0.1"}
    mdata = {"ipv4": minion_ips, "ipv6": []}
    mdata2 = {"ipv4": [minion2_ip], "ipv6": []}
    patch_net = patch("salt.utils.network.local_port_tcp", return_value=minion_ips)
    patch_remote_net = patch(
        "salt.utils.network.remote_port_tcp", return_value={minion2_ip}
    )
    patch_list = patch("salt.cache.Cache.list", return_value=[minion, minion2])
    patch_fetch = patch("salt.cache.Cache.fetch", side_effect=[mdata, mdata2])
    ckminions = salt.utils.minions.CkMinions(opts)
    with patch_net, patch_list, patch_fetch, patch_remote_net:
        ret = ckminions.connected_ids()
        assert ret == {minion2, minion}


# These validate_tgt tests make the assumption that CkMinions.check_minions is
# correct. In other words, these tests are only worthwhile if check_minions is
# also correct.
def test_validate_tgt_returns_true_when_no_valid_minions_have_been_found():
    """
    CKMinions is only able to check against minions the master knows about. If
    no minion keys have been accepted it will return True.
    """
    opts = salt.config.master_config(None)
    ckminions = salt.utils.minions.CkMinions(opts=opts)
    with patch(
        "salt.utils.minions.CkMinions.check_minions", autospec=True, return_value={}
    ):
        result = ckminions.validate_tgt("fnord", "fnord", "fnord", minions=[])
        assert result is True


@pytest.mark.parametrize(
    "valid_minions, target_minions",
    [
        (["one", "two", "three"], ["one", "two", "five"]),
        (["one"], ["one", "two"]),
        (["one", "two", "three", "four"], ["five"]),
    ],
)
def test_validate_tgt_should_return_false_when_minions_have_minions_not_in_valid_minions(
    valid_minions, target_minions
):
    opts = salt.config.master_config(None)
    ckminions = salt.utils.minions.CkMinions(opts=opts)
    with patch(
        "salt.utils.minions.CkMinions.check_minions",
        autospec=True,
        return_value={"minions": valid_minions},
    ):
        result = ckminions.validate_tgt(
            "fnord", "fnord", "fnord", minions=target_minions
        )
        assert result is False


@pytest.mark.parametrize(
    "valid_minions, target_minions",
    [
        (["one", "two", "three", "five"], ["one", "two", "five"]),
        (["one"], ["one"]),
        (["one", "two", "three", "four", "five"], ["five"]),
    ],
)
def test_validate_tgt_should_return_true_when_all_minions_are_found_in_valid_minions(
    valid_minions, target_minions
):
    opts = salt.config.master_config(None)
    ckminions = salt.utils.minions.CkMinions(opts=opts)
    with patch(
        "salt.utils.minions.CkMinions.check_minions",
        autospec=True,
        return_value={"minions": valid_minions},
    ):
        result = ckminions.validate_tgt(
            "fnord", "fnord", "fnord", minions=target_minions
        )
        assert result is True


def test_grain_target_excludes_minions_missing_from_cache(tmp_path):
    """
    Regression test for #68976: grain targeting must not include minions
    whose grain cache entry is missing.

    When the master receives ``salt -G 'asd:def' ...`` and a minion has an
    accepted key but no entry in the master's grain cache (e.g. the minion
    has been offline long enough that its cache directory was pruned, or
    has never returned data), ``CkMinions._check_cache_minions`` with the
    default ``greedy=True`` previously added that minion to the result set
    regardless of the grain expression. The minion would then be added to
    the "missing returners" wait list and reported as not returning.

    Only minions whose cached grains actually match the expression should
    be returned.
    """
    pki_dir = tmp_path / "pki"
    minions_dir = pki_dir / "minions"
    minions_dir.mkdir(parents=True)
    matching_minion = "matching_minion"
    nonmatching_minion = "nonmatching_minion"
    uncached_minion = "uncached_minion"
    for mid in (matching_minion, nonmatching_minion, uncached_minion):
        (minions_dir / mid).write_text("")

    opts = {
        "pki_dir": str(pki_dir),
        "minion_data_cache": True,
        "key_cache": False,
        "transport": "zeromq",
        "extension_modules": str(tmp_path / "extmods"),
        "cachedir": str(tmp_path / "cache"),
        # ``salt.key.Key.__init__`` (used by ``CkMinions``) reads this
        # directly; without it the helper raises KeyError before the
        # cache mocks below get a chance to run.
        "keys.cache_driver": "localfs_key",
        "__role": "master",
    }

    # On 3008.x ``_check_cache_minions`` calls
    # ``self.cache.fetch(search_type, minion_id)`` against a per-bank
    # store (e.g. ``self.cache.fetch("grains", "matching_minion")``)
    # and returns the bare grain dict, not the legacy
    # ``minions/<id>``/``data`` envelope used on 3006.x/3007.x.  Mirror
    # that layout in the fake.
    cache_data = {
        matching_minion: {"asd": "def"},
        nonmatching_minion: {"asd": "other"},
        # uncached_minion intentionally absent
    }

    def fake_list(bank):
        return list(cache_data)

    def fake_fetch(bank, key):
        return cache_data.get(key)

    ckminions = salt.utils.minions.CkMinions(opts)
    # Bypass ``_pki_minions`` (which goes through ``salt.key.Key`` and the
    # configured ``keys.cache_driver``); the bug under test lives in
    # ``_check_cache_minions``, not in the on-disk key listing.
    pki_minions = {matching_minion, nonmatching_minion, uncached_minion}
    with patch.object(
        ckminions, "_pki_minions", return_value=pki_minions
    ), patch.object(ckminions.cache, "list", side_effect=fake_list), patch.object(
        ckminions.cache, "fetch", side_effect=fake_fetch
    ):
        result = ckminions.check_minions("asd:def", "grain")

    assert uncached_minion not in result["minions"], (
        "Minion with no cached grain data should not be included in grain "
        "target matches (#68976)"
    )
    assert nonmatching_minion not in result["minions"]
    assert matching_minion in result["minions"]


# ---------------------------------------------------------------------------
# Presence-record path.
#
# When the publish server has recorded which minion is behind each
# connection, that is authoritative and address matching is skipped
# entirely.  Address matching is what cannot see a minion whose connection
# address differs from its cached grains -- NAT, floating IPs, a master in
# another network -- and it is why those minions were reported absent.
# ---------------------------------------------------------------------------


@pytest.fixture
def presence_opts(tmp_path):
    opts = salt.config.minion_config(None)
    opts.update(
        {
            "publish_port": 4505,
            "detect_remote_minions": False,
            "minion_data_cache": True,
            "__role": "master",
            "cachedir": str(tmp_path),
        }
    )
    return opts


def _no_matching_addresses():
    """Patches that make address matching find nothing, as under NAT."""
    return (
        patch("salt.utils.network.local_port_tcp", return_value={"198.51.100.9"}),
        patch("salt.cache.Cache.list", return_value=["natted-minion"]),
        patch(
            "salt.cache.Cache.fetch", return_value={"ipv4": ["10.0.0.5"], "ipv6": []}
        ),
    )


def test_connected_ids_prefers_the_presence_record(presence_opts):
    """
    The minion's grains say 10.0.0.5, the master sees a connection from
    198.51.100.9, and they never match -- so address matching reports it
    absent while it is perfectly reachable.  The record names it directly.
    """
    salt.utils.presence.write(
        presence_opts, {"natted-minion": "198.51.100.9"}, uptime=600.0
    )
    ckminions = salt.utils.minions.CkMinions(presence_opts)
    patch_net, patch_list, patch_fetch = _no_matching_addresses()
    with patch_net, patch_list, patch_fetch:
        assert ckminions.connected_ids() == {"natted-minion"}


def test_connected_ids_without_a_record_still_matches_addresses(presence_opts):
    """No record means no answer, so the old detection must still run."""
    minion_ips = {"203.0.113.1", "127.0.0.1"}
    patch_net = patch("salt.utils.network.local_port_tcp", return_value=minion_ips)
    patch_list = patch("salt.cache.Cache.list", return_value=["minion"])
    patch_fetch = patch(
        "salt.cache.Cache.fetch", return_value={"ipv4": minion_ips, "ipv6": []}
    )
    ckminions = salt.utils.minions.CkMinions(presence_opts)
    with patch_net, patch_list, patch_fetch:
        assert ckminions.connected_ids() == {"minion"}


def test_connected_ids_falls_back_when_the_record_is_stale(presence_opts):
    """
    A dead publish server must not read as an empty fleet.  This is the
    dangerous direction: ``connected_ids`` also gates ``max_minions`` and
    builds the target list for ``ping_all_connected_minions``.
    """
    salt.utils.presence.write(
        presence_opts, {"natted-minion": "198.51.100.9"}, uptime=600.0
    )
    minion_ips = {"203.0.113.1", "127.0.0.1"}
    patch_net = patch("salt.utils.network.local_port_tcp", return_value=minion_ips)
    patch_list = patch("salt.cache.Cache.list", return_value=["minion"])
    patch_fetch = patch(
        "salt.cache.Cache.fetch", return_value={"ipv4": minion_ips, "ipv6": []}
    )
    patch_stale = patch("salt.utils.presence.STALE_AFTER", -1)
    ckminions = salt.utils.minions.CkMinions(presence_opts)
    with patch_net, patch_list, patch_fetch, patch_stale:
        assert ckminions.connected_ids() == {"minion"}


def test_connected_ids_falls_back_rather_than_reporting_an_empty_fleet(
    presence_opts,
):
    """
    A record listing nobody is produced both by a master with nothing
    connected and by one that cannot name its subscribers -- minions too
    old to announce themselves.  Reporting ``set()`` for the second would
    declare a healthy fleet absent, so an empty answer sends the caller to
    address matching instead.  Here address matching can see the minion,
    and that is the answer that should come back.
    """
    salt.utils.presence.write(presence_opts, {}, uptime=600.0)
    minion_ips = {"203.0.113.1", "127.0.0.1"}
    patch_net = patch("salt.utils.network.local_port_tcp", return_value=minion_ips)
    patch_list = patch("salt.cache.Cache.list", return_value=["minion"])
    patch_fetch = patch(
        "salt.cache.Cache.fetch", return_value={"ipv4": minion_ips, "ipv6": []}
    )
    ckminions = salt.utils.minions.CkMinions(presence_opts)
    with patch_net, patch_list, patch_fetch:
        assert ckminions.connected_ids() == {"minion"}


def test_connected_ids_honours_subset(presence_opts):
    salt.utils.presence.write(
        presence_opts,
        {"one": "10.0.0.1", "two": "10.0.0.2", "three": "10.0.0.3"},
        uptime=600.0,
    )
    ckminions = salt.utils.minions.CkMinions(presence_opts)
    assert ckminions.connected_ids(subset=["one", "three", "absent"]) == {
        "one",
        "three",
    }


def test_connected_ids_show_ip_reports_the_connecting_address(presence_opts):
    """
    The address a minion connects *from*, not an address it claims in its
    grains.  For a NAT'd fleet those differ, and the connecting one is the
    answer the old implementation could never give.
    """
    salt.utils.presence.write(
        presence_opts, {"natted-minion": "198.51.100.9"}, uptime=600.0
    )
    ckminions = salt.utils.minions.CkMinions(presence_opts)
    assert ckminions.connected_ids(show_ip=True) == {("natted-minion", "198.51.100.9")}


def test_connected_ids_works_without_the_minion_data_cache(presence_opts):
    """
    Address matching needs cached grains and bails out entirely without
    them, so ``manage.present`` was unconditionally empty with
    ``minion_data_cache: False``.  The record needs no grains at all.
    """
    presence_opts["minion_data_cache"] = False
    salt.utils.presence.write(presence_opts, {"minion-one": ""}, uptime=600.0)
    ckminions = salt.utils.minions.CkMinions(presence_opts)
    assert ckminions.connected_ids() == {"minion-one"}


def test_connected_ids_still_detects_remote_minions(presence_opts):
    """
    ``detect_remote_minions`` finds Heist-Salt minions by their connection to
    ``remote_minions_port``, which is not the publish port and so is nothing
    a publish server can know about.  Answering from the record alone would
    drop them the moment one exists, against that option's documented
    promise to affect everything calling ``connected_ids()``.
    """
    presence_opts.update({"detect_remote_minions": True, "remote_minions_port": 22})
    salt.utils.presence.write(
        presence_opts, {"natted-minion": "198.51.100.9"}, uptime=600.0
    )
    ckminions = salt.utils.minions.CkMinions(presence_opts)
    with patch("salt.utils.network.local_port_tcp", return_value=set()), patch(
        "salt.utils.network.remote_port_tcp", return_value={"192.168.2.10"}
    ), patch("salt.cache.Cache.list", return_value=["heist-minion"]), patch(
        "salt.cache.Cache.fetch", return_value={"ipv4": ["192.168.2.10"], "ipv6": []}
    ):
        assert ckminions.connected_ids() == {"natted-minion", "heist-minion"}
        assert ckminions.connected_ids(show_ip=True) == {
            ("natted-minion", "198.51.100.9"),
            ("heist-minion", "192.168.2.10"),
        }


def test_a_partly_upgraded_fleet_is_not_reported_absent(presence_opts):
    """
    The record only names subscribers new enough to announce themselves.
    On the normal rollout order -- enable the option on the master, then
    upgrade minions -- it names a handful out of the whole fleet.

    Answering from it alone would trade #66295's false-absent bug for a
    far broader one: ``manage.not_present`` would list every minion not
    yet upgraded, and ``max_minions`` would count the handful and
    silently stop enforcing. The union cannot under-report relative to
    the address matching Salt has always done, so the limit can only ever
    fail closed.
    """
    salt.utils.presence.write(
        presence_opts, {"new-enough": "198.51.100.9"}, uptime=600.0
    )
    ckminions = salt.utils.minions.CkMinions(presence_opts)

    with patch.object(
        ckminions,
        "_connected_ids_by_address",
        return_value={("old-one", "10.0.0.1"), ("old-two", "10.0.0.2")},
    ):
        assert ckminions.connected_ids() == {"new-enough", "old-one", "old-two"}


def test_the_record_wins_for_any_id_it_names(presence_opts):
    """
    Both sources can name the same minion, and they disagree exactly when
    this feature matters: the record carries the real connection address,
    address matching carries whatever the stale grain said.
    """
    salt.utils.presence.write(
        presence_opts, {"natted-minion": "198.51.100.9"}, uptime=600.0
    )
    ckminions = salt.utils.minions.CkMinions(presence_opts)

    with patch.object(
        ckminions,
        "_connected_ids_by_address",
        return_value={("natted-minion", "10.0.0.1")},
    ):
        assert ckminions.connected_ids(show_ip=True) == {
            ("natted-minion", "198.51.100.9")
        }


def test_connected_ids_show_ip_on_the_fallback_path(presence_opts):
    """
    With no record the answer comes from address matching, and it still has
    to be a set of ``(id, address)`` pairs.  ``manage.present show_ip=True``
    does ``dict(minions)`` on the result, so bare ids there raise
    ``ValueError`` rather than returning a wrong answer.
    """
    ckminions = salt.utils.minions.CkMinions(presence_opts)
    assert salt.utils.presence.read(presence_opts) is None, "no record for this test"

    with patch(
        "salt.utils.network.local_port_tcp", return_value={"192.168.2.10"}
    ), patch("salt.cache.Cache.list", return_value=["grain-matched"]), patch(
        "salt.cache.Cache.fetch", return_value={"ipv4": ["192.168.2.10"], "ipv6": []}
    ):
        assert ckminions.connected_ids(show_ip=True) == {
            ("grain-matched", "192.168.2.10")
        }
        assert dict(ckminions.connected_ids(show_ip=True)) == {
            "grain-matched": "192.168.2.10"
        }


def test_the_connecting_address_wins_over_the_grain_address(presence_opts):
    """
    When both mechanisms name the same minion, the publish server's address
    is the one it is actually connected from; the grain address is what
    merely happened to match the socket table.  Letting the grain win would
    reinstate the misleading half of the bug this fixes, in ``show_ip``
    output, for exactly the NAT'd minions it is about.
    """
    presence_opts.update({"detect_remote_minions": True, "remote_minions_port": 22})
    salt.utils.presence.write(
        presence_opts, {"natted-minion": "198.51.100.9"}, uptime=600.0
    )
    ckminions = salt.utils.minions.CkMinions(presence_opts)

    with patch("salt.utils.network.local_port_tcp", return_value={"10.0.0.5"}), patch(
        "salt.utils.network.remote_port_tcp", return_value=set()
    ), patch("salt.cache.Cache.list", return_value=["natted-minion"]), patch(
        "salt.cache.Cache.fetch", return_value={"ipv4": ["10.0.0.5"], "ipv6": []}
    ):
        assert ckminions.connected_ids(show_ip=True) == {
            ("natted-minion", "198.51.100.9")
        }


def test_an_unknown_address_is_filled_in_from_the_grains(presence_opts):
    """
    The connection address wins over the grain address -- except when there
    is no connection address. ZeroMQ reports none over IPC, and an empty
    string is "unknown", not "nowhere", so a grain match is better than
    nothing there. This is the one case where the grain address is used
    for a minion the record already names.
    """
    presence_opts.update({"detect_remote_minions": True, "remote_minions_port": 22})
    salt.utils.presence.write(presence_opts, {"ipc-minion": ""}, uptime=600.0)
    ckminions = salt.utils.minions.CkMinions(presence_opts)

    with patch("salt.utils.network.local_port_tcp", return_value={"10.0.0.5"}), patch(
        "salt.utils.network.remote_port_tcp", return_value=set()
    ), patch("salt.cache.Cache.list", return_value=["ipc-minion"]), patch(
        "salt.cache.Cache.fetch", return_value={"ipv4": ["10.0.0.5"], "ipv6": []}
    ):
        assert ckminions.connected_ids(show_ip=True) == {("ipc-minion", "10.0.0.5")}


def test_a_dual_stack_address_choice_is_stable(presence_opts):
    """
    A dual-stack minion matches twice -- once from its ``ipv4`` grain and
    once from ``ipv6`` -- and the merge can keep only one. Address
    matching returns a set, which a different hash seed iterates in a
    different order, so ``manage.present show_ip=True`` reported a
    different address for the same minion from run to run.

    Both orderings are fed in explicitly: within a single process a set
    of the same two strings iterates the same way every time, so looping
    would not detect this. The rule that settles it is "lowest sorts
    first" -- arbitrary, but specified and stable, which is the property
    that matters.
    """
    salt.utils.presence.write(presence_opts, {"other": "198.51.100.1"}, uptime=600.0)
    ckminions = salt.utils.minions.CkMinions(presence_opts)

    answers = set()
    for ordering in (
        [("dual", "10.0.0.5"), ("dual", "fd00::5")],
        [("dual", "fd00::5"), ("dual", "10.0.0.5")],
    ):
        with patch.object(
            ckminions, "_connected_ids_by_address", return_value=ordering
        ):
            answers.add(dict(ckminions.connected_ids(show_ip=True))["dual"])

    assert answers == {"10.0.0.5"}, f"address depended on iteration order: {answers}"


def test_the_answer_never_exceeds_the_subset(presence_opts):
    """
    ``connected_ids(subset=[...])`` must not name minions the caller did
    not ask about. The record is filtered by subset, but address
    matching is passed the subset too and nothing pins that -- dropping
    it leaks the whole fleet into a ``manage.list_state(subset=...)``.

    Address matching is patched because with it unpatched there is
    nothing on the box to find, so the leak would be invisible.
    """
    salt.utils.presence.write(
        presence_opts, {"asked-for": "", "not-asked-for": ""}, uptime=600.0
    )
    ckminions = salt.utils.minions.CkMinions(presence_opts)

    seen = {}

    def by_address(subset=None, show_ip=False):
        # Faithful to production, which does ``if subset: search = subset``
        # and so cannot return anything outside it. What this test pins is
        # that the subset is *handed over* at all -- passing ``None`` is
        # the regression, and it leaks the whole fleet.
        seen["subset"] = subset
        found = {("asked-for", "10.0.0.1"), ("a-stranger", "10.0.0.2")}
        if subset:
            found = {pair for pair in found if pair[0] in subset}
        return found

    with patch.object(ckminions, "_connected_ids_by_address", by_address):
        answer = ckminions.connected_ids(subset=["asked-for"])

    assert seen["subset"] == ["asked-for"], (
        "address matching was asked for the whole fleet, so anything it "
        "finds leaks past the caller's subset"
    )
    assert answer == {"asked-for"}


def test_a_minion_with_no_known_address_still_appears_with_show_ip(presence_opts):
    """
    zeromq over IPC reports no peer address, so the record carries an
    empty string. Filtering those out would make a minion visible in
    ``manage.present`` but absent from ``manage.present show_ip=True``
    -- two answers to the same question.
    """
    salt.utils.presence.write(
        presence_opts, {"ipc-minion": "", "natted": "198.51.100.9"}, uptime=600.0
    )
    ckminions = salt.utils.minions.CkMinions(presence_opts)

    with patch.object(ckminions, "_connected_ids_by_address", return_value=set()):
        plain = ckminions.connected_ids()
        with_ip = dict(ckminions.connected_ids(show_ip=True))

    assert plain == {"ipc-minion", "natted"}
    assert set(with_ip) == plain, (
        f"show_ip dropped {plain - set(with_ip)}; the same minion is "
        "present or absent depending on how you ask"
    )
    assert with_ip["ipc-minion"] == ""
