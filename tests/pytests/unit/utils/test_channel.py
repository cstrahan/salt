"""
Tests for salt.utils.channel.
"""

import pytest

import salt.utils.channel

pytestmark = [
    pytest.mark.core_test,
]


@pytest.mark.parametrize(
    "opts,expected",
    [
        # tcp authenticates subscribers over the connection, so the publish
        # server knows which minion each one is.
        ({"transport": "tcp"}, True),
        # Plain zeromq subscribes to the empty topic: no identity.
        ({"transport": "zeromq"}, False),
        ({"transport": "zeromq", "zmq_filtering": False}, False),
        # zmq_filtering is deliberately NOT a presence source. The topic it
        # makes a minion subscribe to is derived from the id alone, so
        # accepting it would let anything able to reach the publish port
        # name itself any minion -- and it would switch presence on for
        # deployments that never asked for it.
        ({"transport": "zeromq", "zmq_filtering": True}, False),
        # Announced identity works without filtering, and is the only thing
        # that names a syndic.
        ({"transport": "zeromq", "zmq_presence_subscriptions": True}, True),
        # Filtering neither enables nor disables it; only the one option does.
        (
            {
                "transport": "zeromq",
                "zmq_filtering": True,
                "zmq_presence_subscriptions": True,
            },
            True,
        ),
        (
            {
                "transport": "zeromq",
                "zmq_filtering": False,
                "zmq_presence_subscriptions": False,
            },
            False,
        ),
        # ws has no presence reporting of its own.
        ({"transport": "ws"}, False),
        ({"transport": "ws", "zmq_filtering": True}, False),
        ({"transport": "ws", "zmq_presence_subscriptions": True}, False),
        # Two transports means two publish servers, each knowing only its own
        # subscribers.  Letting them report presence would have each firing a
        # ``salt/presence/present`` listing half the fleet, so a mixed
        # configuration falls back however capable its transports are --
        # here both of them could name a minion on their own.
        (
            {
                "transport": "zeromq",
                "zmq_filtering": True,
                "transport_opts": {"tcp": {}, "zeromq": {}},
            },
            False,
        ),
        (
            {"transport": "tcp", "transport_opts": {"tcp": {}}},
            True,
        ),
        # A ``transport_opts`` entry overrides the option for that transport,
        # and the answer has to follow it either way.  ``Maintenance`` asks
        # this of the raw master opts while the publish server asks it of the
        # per-transport opts, so reading the top-level value instead would
        # have them disagree -- and then either both report presence or
        # neither does.
        (
            {
                "transport": "zeromq",
                "transport_opts": {"zeromq": {"zmq_presence_subscriptions": True}},
            },
            True,
        ),
        (
            {
                "transport": "zeromq",
                "zmq_presence_subscriptions": True,
                "transport_opts": {"zeromq": {"zmq_presence_subscriptions": False}},
            },
            False,
        ),
    ],
)
def test_transport_provides_presence(opts, expected):
    assert salt.utils.channel.transport_provides_presence(opts) is expected


def test_transport_defaults_to_zeromq():
    """
    ``transport`` is optional and defaults to zeromq, which cannot report
    presence unless asked to.
    """
    assert salt.utils.channel.transport_provides_presence({}) is False
    assert (
        salt.utils.channel.transport_provides_presence({"zmq_filtering": True}) is False
    )
    assert (
        salt.utils.channel.transport_provides_presence(
            {"zmq_presence_subscriptions": True}
        )
        is True
    )
