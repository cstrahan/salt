"""
Unit tests for salt transports PublishServer.
"""

import importlib
import inspect

import pytest

import salt.transport.base
from tests.support.mock import MagicMock, patch


@pytest.mark.parametrize("kind", salt.transport.base.TRANSPORTS)
def test_transport_publishserver_has_abstractmethods(kind):
    transport_mod = importlib.import_module(f"salt.transport.{kind}")
    abstractmethods = sorted(
        salt.transport.base.DaemonizedPublishServer.__abstractmethods__
    )
    implemented = []
    for methodname in abstractmethods:
        method = getattr(transport_mod.PublishServer, methodname)
        if not getattr(method, "__isabstractmethod__", False):
            implemented.append(methodname)
    assert implemented == abstractmethods


@pytest.mark.parametrize("kind", salt.transport.base.TRANSPORTS)
@pytest.mark.parametrize(
    "method", salt.transport.base.DaemonizedPublishServer.__abstractmethods__
)
def test_transport_publishserver_has_method_signatures(kind, method):
    transport_mod = importlib.import_module(f"salt.transport.{kind}")
    method_sig = inspect.signature(getattr(transport_mod.PublishServer, method))
    required_sig = inspect.signature(
        getattr(salt.transport.base.DaemonizedPublishServer, method)
    )
    if method == "__init__":
        # Treat init slightly differently. All other methods are generic and should have identical
        # signatures. The __init__ function is called by the factory method which is expected to have
        # knowledge of what parameters are available. Therefore we only check that the arguments
        # found on the Base class are on the child class and ignore any extras.
        method_params = list(method_sig.parameters.items())
        required_params = list(required_sig.parameters.items())
        assert method_params[: len(required_params)] == required_params
    else:
        # This print "OK" when it errors, but you have to dig through the message to find the
        # difference. It may make more sense to create a easier to digest datastructure (list/dict).
        assert method_sig == required_sig


@pytest.mark.parametrize("kind", salt.transport.base.TRANSPORTS)
def test_transport_publishserver_schedules_on_start(kind):
    """
    ``on_start`` is the only chance the channel gets to schedule anything
    on the publish daemon's loop: it runs before that loop exists and then
    blocks inside it.  The presence heartbeat is started this way, and an
    unstarted heartbeat means an idle publish server's record ages into
    stale -- which costs that master its answer and sends every reader
    back to address matching, the thing this feature exists to replace.

    The signature test above pins that each transport *accepts* the
    parameter, and the channel tests pin that it *passes* one. Neither
    notices a transport that accepts it and never calls it.
    """
    transport_mod = importlib.import_module(f"salt.transport.{kind}")
    if kind == "ws":
        pytest.importorskip("aiohttp")
    server = transport_mod.PublishServer.__new__(transport_mod.PublishServer)
    server.opts = {}
    hook = MagicMock()
    loop = MagicMock()
    # run_forever returns at once, so publish_daemon falls through to close.
    with patch.object(transport_mod.PublishServer, "close", MagicMock()), patch(
        "tornado.ioloop.IOLoop", MagicMock(return_value=loop)
    ), patch("salt.utils.asynchronous.aioloop", MagicMock(return_value=loop)):
        try:
            transport_mod.PublishServer.publish_daemon(
                server, MagicMock(), on_start=hook
            )
        except Exception:  # pylint: disable=broad-except
            # Some transports do more setup than a bare object supports;
            # what matters is whether the hook was handed to the loop
            # before that point.
            pass

    scheduled = [
        call
        for name in ("call_soon", "add_callback", "spawn_callback")
        for call in getattr(loop, name).call_args_list
    ]
    assert any(
        hook in call.args for call in scheduled
    ), f"{kind} accepted on_start but never scheduled it: {scheduled}"
