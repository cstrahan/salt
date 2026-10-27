import copy

import salt.master


def iter_transport_opts(opts):
    """
    Yield transport, opts for all master configured transports
    """
    transports = set()
    # Never deepcopy secrets: SMaster.secrets holds SynchronizedString objects
    # (multiprocessing sharedctypes) that Python 3.14 refuses to deepcopy outside
    # a spawning context — assert_spawning() raises even when the start method is
    # "fork".  Exclude the key before copying and re-attach a live reference after,
    # so callers that pass opts already enriched by a previous iter_transport_opts
    # call (e.g. PubServerChannel.factory called from ClearFuncs.connect) are safe.
    opts_nosecrets = {k: v for k, v in opts.items() if k != "secrets"}

    for transport, opts_overrides in opts_nosecrets.get("transport_opts", {}).items():
        t_opts = copy.deepcopy(opts_nosecrets)
        t_opts.update(opts_overrides)
        t_opts["transport"] = transport
        # Ensure secrets are available
        t_opts["secrets"] = salt.master.SMaster.secrets
        transports.add(transport)
        yield transport, t_opts

    transport = opts_nosecrets.get("transport", "zeromq")
    if transport not in transports:
        t_opts = copy.deepcopy(opts_nosecrets)
        t_opts["secrets"] = salt.master.SMaster.secrets
        yield transport, t_opts


def create_server_transport(opts):
    """
    Create a server transport based on opts
    """
    ttype = opts.get("transport", "zeromq")
    if ttype == "zeromq":
        import salt.transport.zeromq

        return salt.transport.zeromq.RequestServer(opts)
    if ttype == "tcp":
        import salt.transport.tcp

        return salt.transport.tcp.RequestServer(opts)
    if ttype == "ws":
        import salt.transport.ws

        return salt.transport.ws.RequestServer(opts)
    raise ValueError(f"Unsupported transport type: {ttype}")


def create_client_transport(opts, io_loop):
    """
    Create a client transport based on opts.
    For request routing, this should return a RequestClient, not PublishClient.
    """
    ttype = opts.get("transport", "zeromq")
    if ttype == "zeromq":
        import salt.transport.zeromq

        # For worker pool routing we need RequestClient, not PublishClient
        if opts.get("workers_ipc_name") or opts.get("pool_name"):
            return salt.transport.zeromq.RequestClient(opts, io_loop=io_loop)
        return salt.transport.zeromq.PublishClient(opts, io_loop)
    if ttype == "tcp":
        import salt.transport.tcp

        if opts.get("workers_ipc_name") or opts.get("pool_name"):
            return salt.transport.tcp.RequestClient(opts, io_loop=io_loop)
        return salt.transport.tcp.PublishClient(opts, io_loop)
    if ttype == "ws":
        import salt.transport.ws

        if opts.get("workers_ipc_name") or opts.get("pool_name"):
            return salt.transport.ws.RequestClient(opts, io_loop=io_loop)
        return salt.transport.ws.PublishClient(opts, io_loop)
    raise ValueError(f"Unsupported transport type: {ttype}")


def create_request_client(opts, io_loop=None):
    """
    Create a RequestClient for pool routing.
    This ensures we always get a RequestClient regardless of transport.
    """
    ttype = opts.get("transport", "zeromq")
    if io_loop is None:
        import tornado.ioloop

        io_loop = tornado.ioloop.IOLoop.current()

    if ttype == "zeromq":
        import salt.transport.zeromq

        return salt.transport.zeromq.RequestClient(opts, io_loop=io_loop)
    if ttype == "tcp":
        import salt.transport.tcp

        return salt.transport.tcp.RequestClient(opts, io_loop=io_loop)
    if ttype == "ws":
        import salt.transport.ws

        return salt.transport.ws.RequestClient(opts, io_loop=io_loop)
    raise ValueError(f"Unsupported transport type: {ttype}")


def transport_provides_presence(opts):
    """Can the configured transport report minion presence itself?

    True when the master has exactly one transport and it can tell the master
    *which* minion a connection belongs to, so presence needs no inference
    from IP addresses:

    - ``tcp``: subscribers authenticate over the connection, so the publish
      server knows the id directly.
    - ``zeromq`` **with ``zmq_presence_subscriptions``**: subscribers
      announce themselves on a dedicated topic nothing is published to,
      assigned by the master at authentication and derived from a secret
      only the master holds. It works without filtering and is the only
      identity
      a syndic's publish connection carries. Requires minions new enough to
      send it; an older one is invisible, and ``zmq_filtering`` does not
      help, because the topic it makes a minion subscribe to is derived
      from the id alone and so proves nothing.

    Otherwise presence falls back to ``CkMinions.connected_ids()``, which
    matches cached grain IPs against the socket table and therefore
    misreports any minion whose connection address differs from its grains
    (NAT, floating IPs, cross-network masters).

    A master configured with more than one transport is False whatever those
    transports are. Each gets its own publish server, each of which knows
    only its own subscribers, so each would fire a ``salt/presence/present``
    listing half the fleet. ``CkMinions.connected_ids()`` is the only thing
    that sees the whole master.

    Presence is opt-in and only ``zmq_presence_subscriptions`` turns it on.
    ``zmq_filtering`` deliberately has no bearing on it: a deployment that
    already has that option set is not quietly switched onto a different
    presence mechanism on upgrade, and the guessable delivery topic it
    makes minions subscribe to is never accepted as identity.

    Note what moves when this flips to True for an existing deployment. The
    publish server is edge-triggered: it fires ``salt/presence/change`` and
    ``salt/presence/present`` when a subscriber arrives or leaves, where
    ``Maintenance.handle_presence`` fired ``present`` once per
    ``loop_interval`` whether or not anything changed, and persisted the set
    to ``<cachedir>/presence-data``. Consumers polling for that heartbeat see
    the cadence change, and the on-disk cache stops being updated -- so if
    this later flips back to False, Maintenance seeds ``old_present`` from
    whatever was last written (within its one hour TTL) and reports the
    difference as newly lost.

    This predicate decides two things: whether the publish server fires
    the ``salt/presence/*`` events, and whether it maintains the on-disk
    record at all -- ``PubServerChannel._publish_daemon`` removes the
    record when this is False. What it does *not* govern is
    ``presence_events``, which switches the event stream on and off
    independently; and ``CkMinions.connected_ids()`` keys off whether a
    usable record exists rather than off either option. See
    :mod:`salt.utils.presence`.
    """
    transports = dict(iter_transport_opts(opts))
    if len(transports) != 1:
        return False
    ((transport, t_opts),) = transports.items()
    if transport == "tcp":
        return True
    # ``t_opts`` rather than ``opts``: a ``transport_opts`` entry can set
    # either of these for the zeromq transport alone, and this predicate is
    # asked both of the raw master opts (``Maintenance``) and of the
    # per-transport opts (``PubServerChannel.factory``,
    # ``PublishServer.publisher``). Reading the override is what stops those
    # callers disagreeing about who owns presence, which would leave the
    # publish server and ``Maintenance`` both reporting it.
    if transport == "zeromq" and t_opts.get("zmq_presence_subscriptions", False):
        return True
    return False
