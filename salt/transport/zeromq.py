"""
Zeromq transport classes
"""

import asyncio
import asyncio.exceptions
import collections
import datetime
import errno
import hashlib
import hmac
import logging
import multiprocessing
import os
import secrets
import signal
import socket
import stat
import sys
import threading
import time
import uuid
import weakref
import zlib
from random import randint

import tornado
import tornado.concurrent
import tornado.gen
import tornado.ioloop
import tornado.locks
import tornado.queues
import zmq.asyncio
import zmq.error
import zmq.eventloop.future
import zmq.eventloop.zmqstream

import salt._process_role
import salt.payload
import salt.transport.base
import salt.utils.asynchronous
import salt.utils.files
import salt.utils.process
import salt.utils.presence
import salt.utils.stringutils
import salt.utils.zeromq
from salt._compat import ipaddress
from salt.exceptions import SaltClientError, SaltException, SaltReqTimeoutError
from salt.utils.zeromq import LIBZMQ_VERSION_INFO, ZMQ_VERSION_INFO, zmq

try:
    import zmq.utils.monitor

    HAS_ZMQ_MONITOR = True
except ImportError:
    HAS_ZMQ_MONITOR = False


log = logging.getLogger(__name__)

# Prefix of the subscription topic every publish subscriber announces its
# identity on: ``PRESENCE_TOPIC_PREFIX`` + the digest the master assigned it.
#
# The master never publishes to this prefix -- published topics are sha1
# hexdigests, ``broadcast`` and ``syndic`` -- so the subscription carries
# identity without carrying any traffic. That is what lets the publish server
# name the subscriber behind a connection (see
# ``PublishServer._subscription_presence``) for *every* role rather than only
# for the roles whose delivery topic happens to be identity-bearing.
#
# A syndic cannot simply subscribe to its own delivery topic instead: the
# master publishes jobs to sha1(minion_id) for each targeted minion, a syndic is
# normally an accepted minion of its master of masters, and a syndic that
# received such a job would forward it to its entire sub-tree.
PRESENCE_TOPIC_PREFIX = b"__salt_presence__:"


#: Length of the hex digest ``salt.utils.presence.topic_for`` produces.
_TOPIC_HEX_LEN = hashlib.sha256().digest_size * 2

#: Longest subscription topic this reader will decode. Every topic it
#: resolves is ``PRESENCE_TOPIC_PREFIX`` plus ``_TOPIC_HEX_LEN`` hex
#: characters, so a couple of hundred bytes is already far more than any
#: of them. The cap matters because the frames arrive from unauthenticated
#: peers and decoding one costs several times its size.
_MAX_TOPIC_LEN = 256

#: Largest message the publish socket will accept from a subscriber when it
#: is an XPUB. 0MQ drops the offending peer's connection rather than
#: delivering anything over this.
_MAX_SUBSCRIPTION_MSG = 8192

# Payload marker for AsyncReqMessageClient queue: stop _send_recv gracefully.
_REQ_QUEUE_SHUTDOWN = object()

# Per-process 24-bit random slot used to disambiguate concurrent salt CLI
# processes claiming the same host/uid/role IDENTITY on the master's ROUTER.
# ``os.getpid() % 256`` -- previously used here -- collides with probability
# ~50% at ~19 concurrent CLIs (birthday bound) and often much sooner in
# practice because the Linux kernel allocates PIDs sequentially: any burst
# of ``salt-call`` from the same shell yields adjacent PIDs whose low byte
# differs but collides again after 256 spawns.  Combined with the master's
# ``ROUTER_HANDOVER=1``, a colliding IDENTITY causes in-flight replies
# queued for one CLI to be re-routed to the sibling, decrypting cleanly
# (same session key) but failing the nonce check -- issue #69753.
# 24 bits (~1 in 16.7M collision probability per pair) is more than enough
# to bound the collision odds across any realistic concurrent CLI load
# while preserving the peer-table-bounding benefit of a stable identity
# for the lifetime of the process.  Computed once at import time so it is
# stable across ZMQ-level reconnects within the process.
_CLI_IDENTITY_SLOT = secrets.randbits(24)


def _get_master_uri(master_ip, master_port, source_ip=None, source_port=None):
    """
    Return the ZeroMQ URI to connect the Minion to the Master.
    It supports different source IP / port, given the ZeroMQ syntax:
    // Connecting using a IP address and bind to an IP address
    rc = zmq_connect(socket, "tcp://192.168.1.17:5555;192.168.1.1:5555"); assert (rc == 0);
    Source: http://api.zeromq.org/4-1:zmq-tcp
    """
    from salt.utils.network import ip_bracket

    master_uri = "tcp://{master_ip}:{master_port}".format(
        master_ip=ip_bracket(master_ip), master_port=master_port
    )

    if source_ip or source_port:
        if LIBZMQ_VERSION_INFO >= (4, 1, 6) and ZMQ_VERSION_INFO >= (16, 0, 1):
            # The source:port syntax for ZeroMQ has been added in libzmq 4.1.6
            # which is included in the pyzmq wheels starting with 16.0.1.
            if source_ip and source_port:
                master_uri = (
                    "tcp://{source_ip}:{source_port};{master_ip}:{master_port}".format(
                        source_ip=ip_bracket(source_ip),
                        source_port=source_port,
                        master_ip=ip_bracket(master_ip),
                        master_port=master_port,
                    )
                )
            elif source_ip and not source_port:
                master_uri = "tcp://{source_ip}:0;{master_ip}:{master_port}".format(
                    source_ip=ip_bracket(source_ip),
                    master_ip=ip_bracket(master_ip),
                    master_port=master_port,
                )
            elif source_port and not source_ip:
                ip_any = (
                    "0.0.0.0"
                    if ipaddress.ip_address(master_ip).version == 4
                    else ip_bracket("::")
                )
                master_uri = (
                    "tcp://{ip_any}:{source_port};{master_ip}:{master_port}".format(
                        ip_any=ip_any,
                        source_port=source_port,
                        master_ip=ip_bracket(master_ip),
                        master_port=master_port,
                    )
                )
        else:
            log.warning(
                "Unable to connect to the Master using a specific source IP / port"
            )
            log.warning("Consider upgrading to pyzmq >= 16.0.1 and libzmq >= 4.1.6")
            log.warning(
                "Specific source IP / port for connecting to master returner port:"
                " configuraion ignored"
            )

    return master_uri


class PublishClient(salt.transport.base.PublishClient):
    """
    A transport channel backed by ZeroMQ for a Salt Publisher to use to
    publish commands to connected minions
    """

    ttype = "zeromq"

    async_methods = [
        "connect",
        "connect_uri",
        "recv",
        # "close",
    ]
    close_methods = [
        "close",
    ]

    def _legacy_setup(
        self,
        _id,
        role,
        zmq_filtering=False,
        tcp_keepalive=True,
        tcp_keepalive_idle=300,
        tcp_keepalive_cnt=-1,
        tcp_keepalive_intvl=-1,
        recon_default=1000,
        recon_max=10000,
        recon_randomize=True,
        ipv6=None,
        master_ip="127.0.0.1",
        zmq_monitor=False,
        **extras,
    ):
        self.hexid = hashlib.sha1(salt.utils.stringutils.to_bytes(_id)).hexdigest()
        self._closing = False
        self.context = zmq.asyncio.Context()
        self._socket = self.context.socket(zmq.SUB)
        self._socket.setsockopt(zmq.LINGER, 1)
        if zmq_filtering:
            # TODO: constants file for "broadcast"
            self._socket.setsockopt(zmq.SUBSCRIBE, b"broadcast")
            if role == "syndic":
                self._socket.setsockopt(zmq.SUBSCRIBE, b"syndic")
            else:
                self._socket.setsockopt(
                    zmq.SUBSCRIBE, salt.utils.stringutils.to_bytes(self.hexid)
                )
        else:
            self._socket.setsockopt(zmq.SUBSCRIBE, b"")

        if _id:
            self._socket.setsockopt(zmq.IDENTITY, salt.utils.stringutils.to_bytes(_id))
        # The announcement subscription is NOT set here. It is derived from
        # the topic the master assigns at authentication, which has
        # not happened yet when this socket is built -- see
        # ``announce_presence``, which the channel calls once it has
        # authenticated and again whenever it re-authenticates.
        self._announced_topic = None

        # TODO: cleanup all the socket opts stuff
        if hasattr(zmq, "TCP_KEEPALIVE"):
            self._socket.setsockopt(zmq.TCP_KEEPALIVE, tcp_keepalive)
            self._socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, tcp_keepalive_idle)
            self._socket.setsockopt(zmq.TCP_KEEPALIVE_CNT, tcp_keepalive_cnt)
            self._socket.setsockopt(zmq.TCP_KEEPALIVE_INTVL, tcp_keepalive_intvl)

        if recon_randomize:
            recon_delay = randint(
                recon_default,
                recon_default + recon_max,
            )

            log.debug(
                "Generated random reconnect delay between '%sms' and '%sms' (%s)",
                recon_delay,
                recon_delay + recon_max,
                recon_delay,
            )

            log.debug("Setting zmq_reconnect_ivl to '%sms'", recon_delay)
            self._socket.setsockopt(zmq.RECONNECT_IVL, recon_delay)

            if hasattr(zmq, "RECONNECT_IVL_MAX"):
                log.debug(
                    "Setting zmq_reconnect_ivl_max to '%sms'",
                    recon_delay + recon_max,
                )

                self._socket.setsockopt(zmq.RECONNECT_IVL_MAX, recon_max)

        if (ipv6 is True or ":" in master_ip) and hasattr(zmq, "IPV4ONLY"):
            # IPv6 sockets work for both IPv6 and IPv4 addresses
            self._socket.setsockopt(zmq.IPV4ONLY, 0)

        self.poller = zmq.Poller()
        self.poller.register(self._socket, zmq.POLLIN)

        if HAS_ZMQ_MONITOR and zmq_monitor:
            self._monitor = ZeroMQSocketMonitor(self._socket)
            self._monitor.start_io_loop(self.io_loop)

    def __init__(self, opts, io_loop, **kwargs):
        super().__init__(opts, io_loop, **kwargs)
        self.opts = opts
        self.io_loop = salt.utils.asynchronous.aioloop(io_loop)
        self._legacy_setup(
            _id=opts.get("id", ""),
            role=opts.get("__role", ""),
            **opts,
        )
        self.connect_called = False
        self.callbacks = {}

        self.host = kwargs.get("host", None)
        self.port = kwargs.get("port", None)
        self.path = kwargs.get("path", None)
        self.source_ip = self.opts.get("source_ip")
        self.source_port = self.opts.get("source_publish_port")
        if self.host is None and self.port is None:
            if self.path is None:
                raise Exception("A host and port or a path must be provided")
        elif self.host and self.port:
            if self.path:
                raise Exception("A host and port or a path must be provided, not both")
        self.on_recv_task = None

    def close(self):
        if self._closing is True:
            return
        self._closing = True
        if hasattr(self, "_monitor") and self._monitor is not None:
            self._monitor.stop()
            self._monitor = None
        # Stop on_recv consumers before tearing down ZMQ; otherwise
        # ``context.destroy`` can block while tasks still await ``recv()``.
        callbacks = self.callbacks
        self.callbacks = {}
        for callback, (running, task) in callbacks.items():
            running.clear()
            try:
                if not task.done():
                    task.cancel()
            except RuntimeError:
                pass
        # Poller and context must be released or each reconnect leaks kernel FDs.
        if hasattr(self, "poller") and self.poller is not None:
            try:
                if getattr(self, "_socket", None) is not None:
                    self.poller.unregister(self._socket)
            except Exception:  # pylint: disable=broad-except
                pass
            self.poller = None
        stream = getattr(self, "_stream", None)
        if stream is not None:
            stream.close(0)
            self._stream = None
        else:
            sock = getattr(self, "_socket", None)
            if sock is not None:
                sock.close(0)
                self._socket = None
        if (
            hasattr(self, "context")
            and self.context is not None
            and not self.context.closed
        ):
            try:
                self.context.destroy(0)
            except Exception:  # pylint: disable=broad-except
                pass
            self.context = None
        return

    # pylint: enable=W1701
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # TODO: this is the time to see if we are connected, maybe use the req channel to guess?
    def announce_presence(self, topic):
        """Announce on the topic the master assigned at authentication.

        Nothing is ever published to it; the subscription exists purely
        to carry identity, which is what makes presence survive NAT
        (#66295).

        The minion derives nothing. It is handed this string inside the
        RSA-encrypted part of its auth reply, so the topic never appears
        in clear in the auth reply -- and because the secret behind it
        does not rotate, there is no re-announcement to make and no
        ordering to get right between a new subscription and cancelling
        an old one.

        The SUBSCRIBE below does put the topic on the wire verbatim;
        ZMTP carries it in the clear absent curve or a tunnel. What the
        encrypted assignment buys is that an attacker who cannot see
        this minion's traffic cannot derive its topic either.
        """
        if not topic:
            return
        if getattr(self, "_socket", None) is None:
            return
        wire = PRESENCE_TOPIC_PREFIX + salt.utils.stringutils.to_bytes(topic)
        if wire == self._announced_topic:
            return
        self._socket.setsockopt(zmq.SUBSCRIBE, wire)
        self._announced_topic = wire

    async def connect(
        self, port=None, connect_callback=None, disconnect_callback=None, timeout=None
    ):
        self._connect_called = True
        if port is not None:
            self.port = port
        if self.path:
            pub_uri = f"ipc://{self.path}"
            log.debug("Connecting the publisher client to: %s", pub_uri)
            self._socket.connect(pub_uri)
        else:
            # host = self.opts["master_ip"],
            if port is not None:
                self.port = port
            master_pub_uri = _get_master_uri(
                self.host, self.port, self.source_ip, self.source_port
            )
            log.debug(
                "Connecting the Minion to the Master publish port, using the URI: %s",
                master_pub_uri,
            )
            self._socket.connect(master_pub_uri)
        if (
            hasattr(self, "_monitor")
            and self._monitor is not None
            and disconnect_callback is not None
        ):
            self._monitor.disconnect_callback = disconnect_callback
        if connect_callback:
            await connect_callback(True)

    async def connect_uri(self, uri, connect_callback=None, disconnect_callback=None):
        self._connect_called = True
        log.debug("Connecting the publisher client to: %s", uri)
        # log.debug("%r connecting to %s", self, self.master_pub)
        self.uri = uri
        self._socket.connect(uri)
        if connect_callback:
            await connect_callback(True)

    def _decode_messages(self, messages):
        """
        Take the zmq messages, decrypt/decode them into a payload

        :param list messages: A list of messages to be decoded
        """
        if isinstance(messages, list):
            messages_len = len(messages)
            # if it was one message, then its old style
            if messages_len == 1:
                payload = salt.payload.loads(messages[0])
            # 2 includes a header which says who should do it
            elif messages_len == 2:
                message_target = salt.utils.stringutils.to_str(messages[0])
                if (
                    self.opts.get("__role") != "syndic"
                    and message_target not in ("broadcast", self.hexid)
                ) or (
                    self.opts.get("__role") == "syndic"
                    and message_target not in ("broadcast", "syndic")
                ):
                    log.debug(
                        "Publish received for not this minion: %s", message_target
                    )
                    return None
                payload = salt.payload.loads(messages[1])
            else:
                raise Exception(
                    "Invalid number of messages ({}) in zeromq pubmessage from master".format(
                        len(messages_len)
                    )
                )
        else:
            payload = salt.payload.loads(messages)
        # Yield control back to the caller. When the payload has been decoded, assign
        # the decoded payload to 'ret' and resume operation
        return payload

    async def recv(self, timeout=None):
        if timeout == 0:
            events = self.poller.poll(timeout=timeout)
            if events:
                return await self._socket.recv()
        elif timeout:
            # Use poll + recv instead of asyncio.wait_for(recv(), timeout).
            # Python 3.12 rewrote wait_for to use asyncio.timeout() which
            # cancels the task via _must_cancel after data has already been
            # consumed from the ZMQ socket.  On a SUB socket this drops the
            # received publish on the floor and subsequent recv calls miss
            # new messages.  poll() never consumes data, so a timeout here
            # is always safe.
            events = await self._socket.poll(timeout=int(timeout * 1000))
            if events:
                return await self._socket.recv()
            log.trace("PublishClient recieve timedout: %s", timeout)
        else:
            return await self._socket.recv()

    async def send(self, msg):
        return
        # raise Exception("Send not supported")
        # await self._socket.send(msg)

    # async def on_recv_handler(self, callback):
    #    while not self._socket:
    #        # Retry quickly, we may want to increase this if it's hogging cpu.
    #        await asyncio.sleep(0.003)
    #    while True:
    #        msg = await self.recv()
    #        if msg:
    #            await callback(msg)

    # def on_recv(self, callback):
    #    """
    #    Register a callback for received messages (that we didn't initiate)
    #    """
    #    if self.on_recv_task:
    #        # XXX: We are not awaiting this canceled task. This still needs to
    #        # be addressed.
    #        self.on_recv_task.cancel()
    #    if callback is None:
    #        self.on_recv_task = None
    #    else:
    #        self.on_recv_task = asyncio.create_task(self.on_recv_handler(callback))

    def on_recv(self, callback):
        """
        Register a callback for received messages (that we didn't initiate)

        :param func callback: A function which should be called when data is received
        """
        if callback is None:
            callbacks = self.callbacks
            self.callbacks = {}
            for callback, (running, task) in callbacks.items():
                running.clear()
                try:
                    if not task.done():
                        task.cancel()
                except RuntimeError:
                    pass
            return

        running = asyncio.Event()
        running.set()

        async def consume(running):
            try:
                while running.is_set():
                    try:
                        msg = await self.recv(timeout=0.3)
                    except zmq.error.ZMQError as exc:
                        # We've disconnected just die
                        break
                    except (asyncio.TimeoutError, asyncio.exceptions.TimeoutError):
                        continue
                    except (
                        asyncio.CancelledError,
                        zmq.eventloop.future.CancelledError,
                    ):
                        break
                    if msg:
                        try:
                            await callback(msg)
                        except Exception:  # pylint: disable=broad-except
                            log.error("Exception while running callback", exc_info=True)
                    # log.debug("Callback done %r", callback)
            except Exception as exc:  # pylint: disable=broad-except
                log.error(
                    "Exception while consuming%s %s", self.uri, exc, exc_info=True
                )

        task = self.io_loop.create_task(consume(running))
        task._log_destroy_pending = False
        self.callbacks[callback] = running, task


class RequestServer(salt.transport.base.DaemonizedRequestServer):
    def __init__(self, opts, secrets=None):  # pylint: disable=W0231
        self.opts = opts
        self.secrets = secrets or opts.get("secrets")

        self._closing = False
        self._monitor = None
        self._w_monitor = None
        self.tasks = set()
        self._event = asyncio.Event()

    def zmq_device(self, secrets=None):
        """
        Multiprocessing target for the zmq queue device
        """
        self.__setup_signals()
        # The first argument to zmq.Context is ``io_threads`` -- the
        # number of background I/O threads libzmq spawns -- not the
        # number of MWorker processes.  Each libzmq I/O thread keeps
        # its own message-buffer pool that grows under sustained
        # traffic and is never released, so passing in
        # ``opts["worker_threads"]`` (typically 5-10) caused the
        # MWorkerQueue process RSS to climb ~7-8 MB/min indefinitely.
        # The QUEUE device only proxies two sockets; one I/O thread is
        # plenty.
        context = zmq.Context(1)
        # Prepare the zeromq sockets
        self.uri = "tcp://{interface}:{ret_port}".format(**self.opts)
        self.clients = context.socket(zmq.ROUTER)
        # LINGER=-1 ("never discard") combined with the salt CLI's pattern
        # of one-shot connections (connect, send, recv, disconnect) caused
        # libzmq to retain undelivered queue slots for every disconnected
        # peer indefinitely under sustained CLI churn.  A small finite
        # LINGER lets libzmq reap those slots.  ROUTER_HANDOVER=1 makes
        # the router swap a stale peer (same routing-id, new connection)
        # instead of blocking on the old one -- relevant for minions that
        # reconnect after a brief network blip.  TCP_KEEPALIVE forces
        # libzmq to notice peers that disappear without sending FIN, so
        # their queues are reaped instead of leaking until the OS default
        # 2-hour idle timer fires.
        self.clients.setsockopt(zmq.LINGER, 1000)
        if hasattr(zmq, "ROUTER_HANDOVER"):
            self.clients.setsockopt(zmq.ROUTER_HANDOVER, 1)
        self.clients.setsockopt(zmq.TCP_KEEPALIVE, 1)
        self.clients.setsockopt(zmq.TCP_KEEPALIVE_IDLE, 60)
        self.clients.setsockopt(zmq.TCP_KEEPALIVE_INTVL, 15)
        self.clients.setsockopt(zmq.TCP_KEEPALIVE_CNT, 3)
        if self.opts["ipv6"] is True and hasattr(zmq, "IPV4ONLY"):
            # IPv6 sockets work for both IPv6 and IPv4 addresses
            self.clients.setsockopt(zmq.IPV4ONLY, 0)
        self.clients.setsockopt(zmq.BACKLOG, self.opts.get("zmq_backlog", 1000))
        self._start_zmq_monitor()
        self.workers = context.socket(zmq.DEALER)
        self.workers.setsockopt(zmq.LINGER, 1000)

        if self.opts["mworker_queue_niceness"] and not salt.utils.platform.is_windows():
            log.info(
                "setting mworker_queue niceness to %d",
                self.opts["mworker_queue_niceness"],
            )
            os.nice(self.opts["mworker_queue_niceness"])

        # Determine worker URI based on pool configuration
        pool_name = self.opts.get("pool_name", "")
        if self.opts.get("ipc_mode", "") == "tcp":
            base_port = self.opts.get("tcp_master_workers", 4515)
            if pool_name:
                # Use different port for each pool
                port_offset = zlib.adler32(pool_name.encode()) % 1000
                self.w_uri = f"tcp://127.0.0.1:{base_port + port_offset}"
            else:
                self.w_uri = f"tcp://127.0.0.1:{base_port}"
        else:
            if pool_name:
                self.w_uri = "ipc://{}".format(
                    os.path.join(self.opts["sock_dir"], f"workers-{pool_name}.ipc")
                )
            else:
                self.w_uri = "ipc://{}".format(
                    os.path.join(self.opts["sock_dir"], "workers.ipc")
                )

        log.info("Setting up the master communication server")
        log.info("RequestServer clients %s", self.uri)
        self.clients.bind(self.uri)
        log.info("RequestServer workers %s", self.w_uri)
        self.workers.bind(self.w_uri)
        if self.opts.get("ipc_mode", "") != "tcp":
            if pool_name:
                ipc_path = os.path.join(
                    self.opts["sock_dir"], f"workers-{pool_name}.ipc"
                )
            else:
                ipc_path = os.path.join(self.opts["sock_dir"], "workers.ipc")
            os.chmod(ipc_path, 0o600)

        # Initialize request router for command classification
        # In non-pooled mode, this is primarily for statistics and consistency
        import salt.master

        router = salt.master.RequestRouter(
            self.opts, secrets=secrets or getattr(self, "secrets", None)
        )

        try:
            while True:
                if self.clients.closed or self.workers.closed:
                    break
                try:
                    zmq.device(zmq.QUEUE, self.clients, self.workers)
                except zmq.ZMQError as exc:
                    if exc.errno == errno.EINTR:
                        continue
                    raise
                except (KeyboardInterrupt, SystemExit):
                    break
        finally:
            # Without an explicit teardown here the local ``context`` goes
            # out of scope with sockets still open, and ``Context.__del__``
            # fires from whatever thread happens to run GC.  Under pyzmq
            # >= 24 that finalizer calls ``destroy()`` which blocks in
            # ``zmq_ctx_term()`` on any queued undeliverable send --
            # indefinitely if the peer is gone.  Sockets here have
            # LINGER=1000/1 (finite) so we can safely close+term.
            if not self.clients.closed:
                self.clients.close()
            if not self.workers.closed:
                self.workers.close()
            context.term()

    def zmq_device_pooled(self, worker_pools, secrets=None):
        """
        Custom ZeroMQ routing device that routes messages to different worker pools
        based on the command in the payload.

        :param dict worker_pools: Dict mapping pool_name to pool configuration
        :param dict secrets: Master secrets for payload decryption
        """
        self.__setup_signals()
        context = zmq.Context(
            sum(p.get("worker_count", 1) for p in worker_pools.values())
        )

        # Create frontend ROUTER socket (minions connect here)
        self.uri = "tcp://{interface}:{ret_port}".format(**self.opts)
        self.clients = context.socket(zmq.ROUTER)
        # PATCH: match the non-pooled ``zmq_device`` socket options exactly.
        # The pooled path was only setting ``LINGER=1``, ``IPV4ONLY``, and
        # ``BACKLOG`` -- missing ZMTP heartbeat, TCP keepalive, and
        # ROUTER_HANDOVER.  Without heartbeat / keepalive, libzmq only
        # reaps dead peers when the OS default TCP keepalive fires
        # (~2h15m on Linux), so anon_pipes / out_pipes entries for
        # long-gone peers accumulate without bound (observed 1000+
        # stuck TCP conns / 9+ GB RSS under sustained CLI + salt-api
        # churn).
        self.clients.setsockopt(zmq.LINGER, 1000)
        if hasattr(zmq, "ROUTER_HANDOVER"):
            self.clients.setsockopt(zmq.ROUTER_HANDOVER, 1)
        _set_zmq_heartbeat(self.clients, self.opts)
        self.clients.setsockopt(zmq.TCP_KEEPALIVE, 1)
        self.clients.setsockopt(zmq.TCP_KEEPALIVE_IDLE, 60)
        self.clients.setsockopt(zmq.TCP_KEEPALIVE_INTVL, 15)
        self.clients.setsockopt(zmq.TCP_KEEPALIVE_CNT, 3)
        if self.opts["ipv6"] is True and hasattr(zmq, "IPV4ONLY"):
            self.clients.setsockopt(zmq.IPV4ONLY, 0)
        self.clients.setsockopt(zmq.BACKLOG, self.opts.get("zmq_backlog", 1000))
        self._start_zmq_monitor()

        if self.opts["mworker_queue_niceness"] and not salt.utils.platform.is_windows():
            log.info(
                "setting mworker_queue niceness to %d",
                self.opts["mworker_queue_niceness"],
            )
            os.nice(self.opts["mworker_queue_niceness"])

        # Create backend DEALER sockets (one per pool) that preserve envelopes
        self.pool_workers = {}
        for pool_name in worker_pools.keys():
            dealer_socket = context.socket(zmq.DEALER)
            dealer_socket.setsockopt(zmq.LINGER, 1)

            # Determine worker URI for this pool
            if self.opts.get("ipc_mode", "") == "tcp":
                base_port = self.opts.get("tcp_master_workers", 4515)
                port_offset = zlib.adler32(pool_name.encode()) % 1000
                w_uri = f"tcp://127.0.0.1:{base_port + port_offset}"
            else:
                w_uri = "ipc://{}".format(
                    os.path.join(self.opts["sock_dir"], f"workers-{pool_name}.ipc")
                )

            log.info("RequestServer pool '%s' workers %s", pool_name, w_uri)
            dealer_socket.bind(w_uri)
            if self.opts.get("ipc_mode", "") != "tcp":
                ipc_path = os.path.join(
                    self.opts["sock_dir"], f"workers-{pool_name}.ipc"
                )
                os.chmod(ipc_path, 0o600)

            self.pool_workers[pool_name] = dealer_socket

        # Initialize request router for command classification
        import salt.master

        router = salt.master.RequestRouter(
            self.opts, secrets=secrets or getattr(self, "secrets", None)
        )

        # Create marker file for _is_master_running() check in netapi
        # This file is expected by components that check if master is running
        if self.opts.get("ipc_mode", "") != "tcp":
            marker_path = os.path.join(self.opts["sock_dir"], "workers.ipc")
            # If workers.ipc exists and is a socket (from a legacy run), remove it
            if os.path.exists(marker_path):
                try:
                    if stat.S_ISSOCK(os.lstat(marker_path).st_mode):
                        log.debug("Removing legacy workers.ipc socket")
                        os.remove(marker_path)
                except OSError:
                    pass
            # Touch the file to create it if it doesn't exist
            try:
                with salt.utils.files.fopen(marker_path, "a", encoding="utf-8"):
                    pass
                os.chmod(marker_path, 0o600)
            except OSError as exc:
                log.error("Failed to create workers.ipc marker file: %s", exc)

        log.info("Setting up pooled master communication server")
        log.info("RequestServer clients %s", self.uri)
        self.clients.bind(self.uri)

        # Poller for receiving from clients and all worker pools
        poller = zmq.Poller()
        poller.register(self.clients, zmq.POLLIN)
        for pool_dealer in self.pool_workers.values():
            poller.register(pool_dealer, zmq.POLLIN)

        try:
            while True:
                if self.clients.closed:
                    break

                try:
                    socks = dict(poller.poll())

                    # Handle incoming responses from worker pools
                    # DEALER preserves the envelope, so we get: [client_id, b"", response]
                    for pool_name, pool_dealer in self.pool_workers.items():
                        if pool_dealer in socks:
                            # Receive message from DEALER (envelope is preserved)
                            msg = pool_dealer.recv_multipart()
                            if len(msg) >= 3:
                                # Forward entire envelope back to ROUTER -> client
                                self.clients.send_multipart(msg)

                    # Handle incoming request from client (minion)
                    if self.clients in socks:
                        # Receive multipart message: [client_id, b"", payload]
                        msg = self.clients.recv_multipart()
                        if len(msg) < 3:
                            continue

                        payload_raw = msg[2]

                        # Decode payload to determine which pool should handle this
                        try:
                            payload = salt.payload.loads(payload_raw)
                            pool_name = router.route_request(payload)

                            if pool_name not in self.pool_workers:
                                log.error(
                                    "Unknown pool '%s' for routing. Using first available pool.",
                                    pool_name,
                                )
                                pool_name = next(iter(self.pool_workers.keys()))

                            # Forward entire envelope to appropriate pool's DEALER
                            # DEALER will preserve the envelope when forwarding to REQ workers
                            pool_dealer = self.pool_workers[pool_name]
                            pool_dealer.send_multipart(msg)

                        except Exception as exc:  # pylint: disable=broad-except
                            log.error("Error routing request: %s", exc, exc_info=True)
                            # Send error response back to client
                            error_payload = salt.payload.dumps(
                                {"error": "Routing error"}
                            )
                            self.clients.send_multipart([msg[0], b"", error_payload])

                except zmq.ZMQError as exc:
                    if exc.errno == errno.EINTR:
                        continue
                    raise
                except (KeyboardInterrupt, SystemExit):
                    break
        finally:
            # Same rationale as zmq_device -- explicitly release sockets
            # and the context so ``Context.__del__`` never has to.
            # Sockets here have LINGER=1000/1 (finite) so close+term is safe.
            for pool_dealer in self.pool_workers.values():
                if not pool_dealer.closed:
                    pool_dealer.close()
            if not self.clients.closed:
                self.clients.close()
            context.term()

    def __setstate__(self, state):
        self.__init__(**state)

    def __getstate__(self):
        return {
            "opts": self.opts,
            "secrets": getattr(self, "secrets", None),
        }

    def close(self):
        """
        Cleanly shutdown the router socket
        """
        if self._closing:
            return
        log.info("MWorkerQueue under PID %s is closing", os.getpid())
        self._closing = True
        self._event.set()
        if getattr(self, "_monitor", None) is not None:
            self._monitor.stop()
            self._monitor = None
        if getattr(self, "_w_monitor", None) is not None:
            self._w_monitor.stop()
            self._w_monitor = None
        if hasattr(self, "clients") and self.clients.closed is False:
            self.clients.close()
        if hasattr(self, "workers") and self.workers.closed is False:
            self.workers.close()
        # Close pool workers if they exist
        if hasattr(self, "pool_workers"):
            for dealer in self.pool_workers.values():
                if not dealer.closed:
                    dealer.close()
        if hasattr(self, "stream"):
            self.stream.close()
        if hasattr(self, "message_client") and self.message_client is not None:
            self.message_client.close()
        if hasattr(self, "_socket") and self._socket.closed is False:
            self._socket.close()
        if hasattr(self, "context") and self.context.closed is False:
            # ``self.context`` here is the ``zmq.asyncio.Context`` created
            # in ``post_fork``.  Using ``destroy(linger=1000)`` rather
            # than ``term()`` mirrors the discipline elsewhere in this
            # module: ``term()`` has no timeout and can block
            # indefinitely in ``zmq_ctx_term()`` if libzmq believes any
            # socket still has queued undeliverable messages, whereas
            # ``destroy(linger=N)`` explicitly caps the wait at ``N`` ms
            # per socket.  1 s is enough to let any legitimate in-flight
            # REP reply flush; the REP worker socket has already been
            # closed above so in practice this returns immediately.
            self.context.destroy(linger=1000)
            self.context = None
        for task in list(self.tasks):
            try:
                task.cancel()
            except RuntimeError:
                log.error("IOLoop closed when trying to cancel task")

    def pre_fork(self, process_manager, *args, **kwargs):
        """
        Pre-fork we need to create the zmq router device

        :param func process_manager: An instance of salt.utils.process.ProcessManager
        :param dict worker_pools: Optional worker pools configuration for pooled routing
        """
        # If we are a pool-specific RequestServer, we don't need a device.
        # We connect directly to the sockets created by the main pooled device.
        if self.opts.get("pool_name"):
            return

        worker_pools = kwargs.get("worker_pools") or (args[0] if args else None)
        secrets = kwargs.get("secrets") or getattr(self, "secrets", None)
        if worker_pools:
            # Use pooled routing device
            process_manager.add_process(
                self.zmq_device_pooled,
                args=(worker_pools,),
                kwargs={"secrets": secrets},
                name="MWorkerQueue",
            )
        else:
            # Use standard routing device
            process_manager.add_process(
                self.zmq_device,
                kwargs={"secrets": secrets},
                name="MWorkerQueue",
            )

    def _start_zmq_monitor(self):
        """
        Starts ZMQ monitor for debugging purposes.
        :return:
        """
        # Socket monitor shall be used the only for debug
        # purposes so using threading doesn't look too bad here

        if HAS_ZMQ_MONITOR and self.opts["zmq_monitor"]:
            log.debug("Starting ZMQ monitor")
            self._w_monitor = ZeroMQSocketMonitor(self._socket)
            threading.Thread(target=self._w_monitor.start_poll).start()
            log.debug("ZMQ monitor has been started started")

    def post_fork(self, message_handler, io_loop, **kwargs):
        """
        After forking we need to create all of the local sockets to listen to the
        router

        :param func message_handler: A function to called to handle incoming payloads as
                                     they are picked up off the wire
        :param IOLoop io_loop: An instance of a Tornado IOLoop, to handle event scheduling
        """
        pool_name = kwargs.get("pool_name")
        # context = zmq.Context(1)
        self.context = zmq.asyncio.Context(1)
        self._socket = self.context.socket(zmq.REP)
        # Linger -1 means we'll never discard messages.
        self._socket.setsockopt(zmq.LINGER, 1)
        self._start_zmq_monitor()

        # Use get_worker_uri() for consistent URI construction
        self.w_uri = self.get_worker_uri(pool_name=pool_name)
        log.info("Worker binding to socket %s", self.w_uri)
        self._socket.connect(self.w_uri)

        # Set permissions for IPC sockets
        if self.opts.get("ipc_mode", "") != "tcp":
            pool_name = self.opts.get("pool_name", "")
            if pool_name:
                ipc_path = os.path.join(
                    self.opts["sock_dir"], f"workers-{pool_name}.ipc"
                )
            else:
                ipc_path = os.path.join(self.opts["sock_dir"], "workers.ipc")
            if os.path.isfile(ipc_path):
                os.chmod(ipc_path, 0o600)
        self.message_handler = message_handler

        async def callback():
            task = asyncio.create_task(
                self.request_handler(), name="RequestServer.request_handler"
            )
            task._log_destroy_pending = False
            task.add_done_callback(self.tasks.discard)

            def _task_done(task):
                try:
                    task.result()
                except (asyncio.CancelledError, zmq.eventloop.future.CancelledError):
                    pass
                except Exception as exc:  # pylint: disable=broad-except
                    log.error(
                        "Unhandled exception in request_handler task: %s",
                        exc,
                        exc_info=True,
                    )

            task.add_done_callback(_task_done)
            self.tasks.add(task)

        callback_task = salt.utils.asynchronous.aioloop(io_loop).create_task(callback())

    async def request_handler(self):
        log.trace("RequestServer.request_handler started")
        try:
            while not self._event.is_set():
                try:
                    # Use poll + recv instead of asyncio.wait_for(recv(), timeout).
                    # Python 3.12 rewrote wait_for to use asyncio.timeout() which
                    # cancels the task via _must_cancel after data has already been
                    # consumed from the ZMQ socket.  On a REP socket this leaves the
                    # FSM in a "received request / expecting send" state permanently,
                    # deadlocking the worker.  poll() never consumes data, so a
                    # timeout here is always safe.
                    events = await self._socket.poll(timeout=300)
                    if not events:
                        continue
                    request = await self._socket.recv()
                    reply = await self.handle_message(None, request)
                    await self._socket.send(self.encode_payload(reply))
                except zmq.error.Again:
                    continue
                except (asyncio.CancelledError, zmq.eventloop.future.CancelledError):
                    break
                except Exception as exc:  # pylint: disable=broad-except
                    log.error(
                        "Exception in request handler: %s",
                        exc,
                        exc_info_on_loglevel=logging.DEBUG,
                    )
                    await asyncio.sleep(0)
                    continue
        finally:
            log.trace("RequestServer.request_handler exiting")

    async def handle_message(self, stream, payload):
        try:
            payload = self.decode_payload(payload)
        except salt.exceptions.SaltDeserializationError:
            return {"msg": "bad load"}
        return await self.message_handler(payload)

    def encode_payload(self, payload):
        return salt.payload.dumps(payload)

    def __setup_signals(self):
        signal.signal(signal.SIGINT, self._handle_signals)
        signal.signal(signal.SIGTERM, self._handle_signals)

    def _handle_signals(self, signum, sigframe):
        msg = f"{self.__class__.__name__} received a "
        if signum == signal.SIGINT:
            msg += "SIGINT"
        elif signum == signal.SIGTERM:
            msg += "SIGTERM"
        msg += ". Exiting"
        log.debug(msg)
        self.close()
        sys.exit(salt.defaults.exitcodes.EX_OK)

    def decode_payload(self, payload):
        payload = salt.payload.loads(payload)
        return payload

    def get_worker_uri(self, pool_name=None):
        """
        Get the URI where workers connect to this transport's queue.
        Used by the dispatcher to know where to forward messages.
        """
        if pool_name is None:
            pool_name = self.opts.get("pool_name", "")

        if self.opts.get("ipc_mode", "") == "tcp":
            if pool_name:
                # Hash pool name for consistent port assignment
                base_port = self.opts.get("tcp_master_workers", 4515)
                port_offset = zlib.adler32(pool_name.encode()) % 1000
                return f"tcp://127.0.0.1:{base_port + port_offset}"
            else:
                return f"tcp://127.0.0.1:{self.opts.get('tcp_master_workers', 4515)}"
        else:
            if pool_name:
                return f"ipc://{os.path.join(self.opts['sock_dir'], f'workers-{pool_name}.ipc')}"
            else:
                return f"ipc://{os.path.join(self.opts['sock_dir'], 'workers.ipc')}"

    async def forward_message(self, payload):
        """
        Forward a message to this transport's worker queue.
        Creates a temporary client connection to send the message.
        """
        context = zmq.asyncio.Context()
        socket = context.socket(zmq.REQ)
        socket.setsockopt(zmq.LINGER, 0)

        try:
            w_uri = self.get_worker_uri()
            socket.connect(w_uri)

            # Send payload
            await socket.send(self.encode_payload(payload))

            # Receive reply (required for REQ/REP pattern)
            reply = await asyncio.wait_for(socket.recv(), timeout=60.0)

            return self.decode_payload(reply)
        finally:
            # This coroutine runs per forwarded message.  Without the
            # explicit ``context.term()`` below, each call leaks a
            # ``zmq.asyncio.Context`` -- eventually GC'd from an asyncio
            # ioloop callback where ``Context.__del__`` -> ``destroy()``
            # can wedge in ``zmq_ctx_term()`` if any socket still has
            # queued undeliverable sends.  The REQ socket has LINGER=0
            # so ``socket.close()`` above already dropped any pending
            # send; the subsequent ``term()`` returns immediately.
            socket.close()
            context.term()


def _set_tcp_keepalive(zmq_socket, opts):
    """
    Ensure that TCP keepalives are set as specified in "opts".

    Warning: Failure to set TCP keepalives on the salt-master can result in
    not detecting the loss of a minion when the connection is lost or when
    its host has been terminated without first closing the socket.
    Salt's Presence System depends on this connection status to know if a minion
    is "present".

    Warning: Failure to set TCP keepalives on minions can result in frequent or
    unexpected disconnects!
    """
    if hasattr(zmq, "TCP_KEEPALIVE") and opts:
        if "tcp_keepalive" in opts:
            zmq_socket.setsockopt(zmq.TCP_KEEPALIVE, opts["tcp_keepalive"])
        if "tcp_keepalive_idle" in opts:
            zmq_socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, opts["tcp_keepalive_idle"])
        if "tcp_keepalive_cnt" in opts:
            zmq_socket.setsockopt(zmq.TCP_KEEPALIVE_CNT, opts["tcp_keepalive_cnt"])
        if "tcp_keepalive_intvl" in opts:
            zmq_socket.setsockopt(zmq.TCP_KEEPALIVE_INTVL, opts["tcp_keepalive_intvl"])


# Defaults are intentionally generous: small enough to reap dead SUB peers
# within seconds (rather than the ~2h15m kernel TCP keepalive default), but
# large enough not to disrupt a healthy fleet of thousands of minions on a
# laggy network.  Operators can tune via ``zmq_heartbeat_ivl`` /
# ``zmq_heartbeat_timeout`` in milliseconds.
_DEFAULT_ZMQ_HEARTBEAT_IVL = 10000  # 10s between heartbeats
_DEFAULT_ZMQ_HEARTBEAT_TIMEOUT = 30000  # 30s with no response -> peer dead


def _set_zmq_heartbeat(zmq_socket, opts):
    """
    Enable ZMTP heartbeats on a ZeroMQ socket.

    Without ``ZMQ_HEARTBEAT_IVL`` / ``ZMQ_HEARTBEAT_TIMEOUT`` configured,
    ZMQ relies on the kernel TCP keepalive to notice a peer that vanished
    without sending FIN (host reboot, kernel panic, dropped firewall rule).
    On Linux that's ~2h15m by default, during which the master's PUB
    socket keeps buffering for the dead peer and ``netstat`` accumulates
    ``CLOSE_WAIT`` entries on port 4505 — eventually the master stops
    accepting new connections.  See
    https://github.com/saltstack/salt/issues/66282.

    Heartbeat opts are configured in milliseconds.  Setting ``ivl`` or
    ``timeout`` to ``0`` disables the corresponding option (matching the
    ZMQ defaults).
    """
    if not opts:
        opts = {}
    ivl = int(opts.get("zmq_heartbeat_ivl", _DEFAULT_ZMQ_HEARTBEAT_IVL))
    timeout = int(opts.get("zmq_heartbeat_timeout", _DEFAULT_ZMQ_HEARTBEAT_TIMEOUT))
    if hasattr(zmq, "HEARTBEAT_IVL"):
        zmq_socket.setsockopt(zmq.HEARTBEAT_IVL, ivl)
    if hasattr(zmq, "HEARTBEAT_TIMEOUT"):
        zmq_socket.setsockopt(zmq.HEARTBEAT_TIMEOUT, timeout)


# TODO: unit tests!
class AsyncReqMessageClient:
    """
    This class wraps the underlying zeromq REQ socket and gives a future-based
    interface to sending and recieving messages. This works around the primary
    limitation of serialized send/recv on the underlying socket by queueing the
    message sends in this class. In the future if we decide to attempt to multiplex
    we can manage a pool of REQ/REP sockets-- but for now we'll just do them in serial
    """

    def __init__(self, opts, addr, linger=0, io_loop=None):
        """
        Create an asynchronous message client

        :param dict opts: The salt opts dictionary
        :param str addr: The interface IP address to bind to
        :param int linger: The number of seconds to linger on a ZMQ socket. See
                           http://api.zeromq.org/2-1:zmq-setsockopt [ZMQ_LINGER]
        :param IOLoop io_loop: A Tornado IOLoop event scheduler [tornado.ioloop.IOLoop]
        """
        salt.utils.versions.warn_until(
            3009,
            "AsyncReqMessageClient has been deprecated and will be removed.",
        )
        self.opts = opts
        self.addr = addr
        self.linger = linger
        if io_loop is None:
            self.io_loop = tornado.ioloop.IOLoop.current()
        else:
            self.io_loop = io_loop
        self._aioloop = salt.utils.asynchronous.aioloop(self.io_loop)
        self.context = zmq.eventloop.future.Context()
        self.socket = None
        self._closed = False
        self._queue = tornado.queues.Queue()
        self._send_recv_exit_future = None

    def connect(self):
        if self.context is None:
            self.context = zmq.eventloop.future.Context()

        if hasattr(self, "socket") and self.socket:
            return
        # wire up sockets
        self._init_socket()

    def _init_socket(self):
        self.socket = self.context.socket(zmq.REQ)

        # socket options
        if hasattr(zmq, "RECONNECT_IVL_MAX"):
            self.socket.setsockopt(zmq.RECONNECT_IVL_MAX, 5000)

        # Set a stable ZMQ routing identity so the master's ROUTER socket
        # reuses an existing slot for this caller (combined with
        # ROUTER_HANDOVER=1 on the master) rather than allocating a new
        # entry in its per-peer table for every CLI invocation.  Without
        # this, the master's libzmq peer-id hashtable grows unbounded
        # under sustained CLI churn (about 6 MB/min in stress).
        #
        # Only do this for salt CLI tools and long-lived minion/syndic
        # daemons.  ``salt-master`` daemons open multiple concurrent
        # AsyncReqMessageClient instances (peer-master forwarding,
        # engines, etc.) and must keep libzmq's default per-connection
        # random routing-ids -- giving them a shared stable identity
        # would cause ROUTER_HANDOVER on the upstream ROUTER to
        # silently drop any reply still in flight.
        #
        # A CLI invocation is detected via ``salt._process_role.is_cli``
        # (flipped by ``salt.scripts`` at entry) *not* via ``__role``:
        # when a salt CLI runs from a master host it loads
        # ``/etc/salt/master`` and inherits ``__role=master``, so a
        # role-only gate would fall through and each connection would
        # get a random routing-id -- which the master's MWorkerQueue
        # ROUTER accepts but never frees the underlying socket FD for.
        # The ``not _role`` branch remains as a fallback for bare CLI
        # invocations where ``__role`` was never populated (older
        # embedded uses, tests, etc.).
        _role = self.opts.get("__role")
        _minion_id = self.opts.get("id")
        if salt._process_role.is_cli() or not _role:
            role = _role or _minion_id or "clir"
            try:
                uid = os.getuid()
            except AttributeError:  # Windows
                uid = 0
            identity = "salt-req/{role}/{host}/{uid}/{slot}".format(
                role=role,
                host=socket.gethostname(),
                uid=uid,
                slot=_CLI_IDENTITY_SLOT,
            )
            self.socket.setsockopt(zmq.IDENTITY, identity.encode("utf-8"))
        elif _role in ("minion", "syndic") and _minion_id:
            # Per-RequestClient UUID: one IDENTITY per instance lifetime, so the
            # master ROUTER's routing-id entry maps 1:1 to a client we open and
            # close ourselves.  Naturally distinct across fork boundaries (each
            # child draws a fresh UUID) so the identity-collision retry class
            # that motivated #69753 is impossible by construction.
            identity = "salt-req/{role}/{minion_id}/{pid}/{uuid}".format(
                role=_role,
                minion_id=_minion_id,
                pid=os.getpid(),
                uuid=uuid.uuid4().hex,
            )
            self.socket.setsockopt(zmq.IDENTITY, identity.encode("utf-8"))

        _set_tcp_keepalive(self.socket, self.opts)
        if self.addr.startswith("tcp://["):
            # Hint PF type if bracket enclosed IPv6 address
            if hasattr(zmq, "IPV6"):
                self.socket.setsockopt(zmq.IPV6, 1)
            elif hasattr(zmq, "IPV4ONLY"):
                self.socket.setsockopt(zmq.IPV4ONLY, 0)
        self.socket.setsockopt(zmq.LINGER, self.linger)
        self.socket.connect(self.addr)
        self.io_loop.spawn_callback(self._send_recv, self.socket)

    def _close_zmq_only(self):
        """Close socket and ZMQ context only (no IOLoop / _send_recv coordination)."""
        if hasattr(self, "socket") and self.socket is not None:
            self.socket.close(0)
            self.socket = None
        if self.context is not None and self.context.closed is False:
            # ``context.term()`` can block indefinitely in ``zmq_ctx_term()``
            # if libzmq believes any socket on the context still has
            # queued undeliverable messages -- even after we called
            # ``socket.close(0)`` above.  Since we call this both from
            # the explicit close path AND from ``_send_recv``'s timeout /
            # reconnect branch (which runs on the owning ioloop), a block
            # here freezes the ioloop.  ``destroy(linger=1000)`` bounds
            # the wait: any socket the context still tracks gets a 1s
            # grace to flush pending sends before terminating, so the
            # call is bounded to O(sockets * 1s) and cannot wedge.  REQ
            # semantics tolerate a bounded flush window -- unlike the
            # PublishServer PUSH path which broke
            # ``test_issue_regression_65265`` when destroyed with
            # linger=0.
            self.context.destroy(linger=1000)
            self.context = None

    def close_future(self):
        """
        Return a ``Future`` that completes after ZMQ resources are released.

        Coroutine callers on the owning I/O loop thread should ``yield`` this future
        (via ``tornado.gen.convert_yielded``) before allocating another
        client on that loop - ``close()`` schedules teardown asynchronously in that
        case.
        """
        self._initiate_async_req_close()
        return self._close_completed_future

    def close(self):
        """
        Stop the send/recv coroutine and close ZMQ resources. Safe to call more
        than once.

        When no I/O loop iteration is active, uses ``run_sync`` around the graceful
        shutdown coroutine (LocalClient/SyncWrapper and similar).

        When the owning ``io_loop`` is already running - including on the master
        event loop thread while short-lived REQ clients are torn down - you cannot
        call ``run_sync``. In that case the shutdown future is queued with
        ``add_callback`` / ``add_future``. If ``close()`` is invoked from another
        thread while the loop is running, we block until shutdown completes.

        On the owning I/O loop thread, prefer ``yield``-ing ``close_future()`` instead
        of ``close()`` when you recreate clients immediately afterward.
        """
        cross_thread_evt = self._initiate_async_req_close()
        if cross_thread_evt is not None:
            cross_thread_evt.wait(timeout=30)

    def _mark_teardown_finished(self):
        fut = getattr(self, "_close_completed_future", None)
        if fut is not None and not fut.done():
            fut.set_result(None)

    def _initiate_async_req_close(self):
        """
        Start teardown once.

        Sets ``self._close_completed_future`` and returns ``None``, or an
        ``threading.Event`` that unblocks after ``finalize()`` when the caller needs
        to wait from a non-I/O-loop thread.
        """
        if getattr(self, "_close_completed_future", None) is not None:
            return None

        self._close_completed_future = tornado.concurrent.Future()
        cross_thread_evt = None

        def finalize():
            self._send_recv_exit_future = None
            self._close_zmq_only()
            self._mark_teardown_finished()
            if cross_thread_evt is not None:
                cross_thread_evt.set()

        def run_shutdown():
            return self._graceful_shutdown_coro()

        if self._closed:
            finalize()
            return None

        self._closed = True
        if self.socket is None:
            finalize()
            return None

        self._send_recv_exit_future = tornado.concurrent.Future()

        # tornado < 6 exposed ``_running`` and ``_thread_ident`` directly on
        # IOLoop. tornado >= 6 wraps an asyncio loop (AsyncIOLoop /
        # AsyncIOMainLoop) and neither attribute is set; fall back to the
        # underlying asyncio loop's own bookkeeping. Without this fallback
        # ``loop_running`` reads False on tornado 6 even when we are inside
        # a running asyncio event loop, sending us into ``run_sync`` (which
        # would raise ``RuntimeError: IOLoop is already running``); and
        # ``same_thread`` reads False on the loop's own thread, sending the
        # caller into ``cross_thread_evt.wait()`` which deadlocks because the
        # scheduled finalize callback can never run while the loop is
        # blocked waiting on the event. See cpython#104135 (separate) /
        # tornado AsyncIOLoop attribute changes.
        loop_running = bool(getattr(self.io_loop, "_running", False))
        asyncio_loop = getattr(self.io_loop, "asyncio_loop", None)
        if not loop_running and asyncio_loop is not None:
            try:
                loop_running = asyncio_loop.is_running()
            except Exception:  # pylint: disable=broad-except
                loop_running = False

        try:
            if not loop_running:
                self.io_loop.run_sync(run_shutdown, timeout=30)
                finalize()
                return None
        except RuntimeError as exc:
            if "already running" not in str(exc).lower():
                log.debug(
                    "REQ client shutdown: run_sync aborted: %s",
                    exc,
                    exc_info=True,
                )
                finalize()
                return None
        except tornado.ioloop.TimeoutError:
            log.debug("Graceful REQ message client shutdown timed out during run_sync")
            finalize()
            return None
        except Exception:  # pylint: disable=broad-except
            log.debug(
                "Graceful REQ message client shutdown failed during run_sync",
                exc_info=True,
            )
            finalize()
            return None

        try:
            shutdown_future = tornado.gen.convert_yielded(
                self._graceful_shutdown_coro()
            )
        except Exception:  # pylint: disable=broad-except
            log.debug(
                "Could not schedule REQ shutdown coroutine while loop is running",
                exc_info=True,
            )
            finalize()
            return None

        ioloop_thread = getattr(self.io_loop, "_thread_ident", None)
        if ioloop_thread is None and asyncio_loop is not None:
            # AsyncIO bookkeeping: ``asyncio_loop._thread_id`` is set while
            # the loop is running.
            ioloop_thread = getattr(asyncio_loop, "_thread_id", None)
        same_thread = (
            ioloop_thread is not None and ioloop_thread == threading.get_ident()
        )
        cross_thread_evt = None if same_thread else threading.Event()

        def on_done(future):
            try:
                future.result()
            except Exception:  # pylint: disable=broad-except
                log.debug(
                    "Graceful REQ message client shutdown failed during async teardown",
                    exc_info=True,
                )
            finally:
                finalize()

        def schedule():
            self.io_loop.add_future(shutdown_future, on_done)

        try:
            self.io_loop.add_callback(schedule)
        except Exception:  # pylint: disable=broad-except
            log.debug(
                "Graceful REQ message client shutdown failed scheduling callback",
                exc_info=True,
            )
            finalize()
            return None

        return cross_thread_evt

    @tornado.gen.coroutine
    def _graceful_shutdown_coro(self):
        try:
            self._queue.put_nowait((tornado.concurrent.Future(), _REQ_QUEUE_SHUTDOWN))
        except Exception:  # pylint: disable=broad-except
            log.debug("Could not queue shutdown sentinel", exc_info=True)
            if self._send_recv_exit_future and not self._send_recv_exit_future.done():
                self._send_recv_exit_future.set_result(None)
            raise tornado.gen.Return()
        yield self._send_recv_exit_future

    @tornado.gen.coroutine
    def send(self, message, timeout=None, callback=None):
        """
        Return a future which will be completed when the message has a response
        """
        future = tornado.concurrent.Future()

        message = salt.payload.dumps(message)

        self._queue.put_nowait((future, message))

        send_timeout = None

        if callback is not None:

            def handle_future(future):
                response = future.result()
                self.io_loop.add_callback(callback, response)

            future.add_done_callback(handle_future)

        if self.opts.get("detect_mode") is True:
            timeout = 1

        if timeout is not None:
            send_timeout = self.io_loop.call_later(
                timeout, self._timeout_message, future
            )

        try:
            recv = yield future
        finally:
            if send_timeout is not None:
                self.io_loop.remove_timeout(send_timeout)

        raise tornado.gen.Return(recv)

    def _timeout_message(self, future):
        if not future.done():
            future.set_exception(SaltReqTimeoutError("Message timed out"))

    @tornado.gen.coroutine
    def _send_recv(self, socket, _TimeoutError=tornado.gen.TimeoutError):
        """
        Long-running send/receive coroutine. This should be started once for
        each socket created. Once started, the coroutine will run until the
        socket is closed. A future and message are pulled from the queue. The
        message is sent and the reply socket is polled for a response while
        checking the future to see if it was timed out.
        """
        send_recv_running = True
        # Hold on to the socket so we'll still have a reference to it after the
        # close method is called. This allows us to fail gracefully once it's
        # been closed.
        try:
            while send_recv_running:
                try:
                    future, message = yield self._queue.get(
                        timeout=datetime.timedelta(milliseconds=300)
                    )
                except _TimeoutError:
                    try:
                        # For some reason yielding here doesn't work becaues the
                        # future always has a result?
                        poll_future = socket.poll(0, zmq.POLLOUT)
                        poll_future.result()
                    except _TimeoutError:
                        # This is what we expect if the socket is still alive
                        pass
                    except zmq.eventloop.future.CancelledError:
                        log.trace("Loop closed while polling send socket.")
                        # The ioloop was closed before polling finished.
                        send_recv_running = False
                        break
                    except zmq.ZMQError:
                        log.trace("Send socket closed while polling.")
                        send_recv_running = False
                        break
                    continue

                if message is _REQ_QUEUE_SHUTDOWN:
                    send_recv_running = False
                    break

                try:
                    yield socket.send(message)
                except zmq.eventloop.future.CancelledError as exc:
                    log.trace("Loop closed while sending.")
                    # The ioloop was closed before polling finished.
                    send_recv_running = False
                    if not future.done():
                        future.set_exception(exc)
                    break
                except zmq.ZMQError as exc:
                    if exc.errno in [
                        zmq.ENOTSOCK,
                        zmq.ETERM,
                        zmq.error.EINTR,
                    ]:
                        log.trace("Send socket closed while sending.")
                        send_recv_running = False
                        if not future.done():
                            future.set_exception(exc)
                    elif exc.errno == zmq.EFSM:
                        log.error("Socket was found in invalid state.")
                        send_recv_running = False
                        if not future.done():
                            future.set_exception(exc)
                    else:
                        log.error(
                            "Unhandled Zeromq error durring send/receive: %s", exc
                        )
                        if not future.done():
                            future.set_exception(exc)

                if future.done():
                    exc = future.exception()
                    if isinstance(exc, SaltReqTimeoutError):
                        log.trace("Request timed out while sending. reconnecting.")
                    else:
                        log.trace(
                            "The request ended with an error while sending. reconnecting."
                        )
                    # Only reconnect if the client is still active. If close()
                    # was already called externally (context is None), do not
                    # create a new socket/context that would never be cleaned up.
                    _should_reconnect = self.context is not None
                    self._close_zmq_only()
                    if _should_reconnect:
                        self.connect()
                    send_recv_running = False
                    break

                received = False
                ready = False
                while True:
                    if future.done():
                        break
                    try:
                        # Time is in milliseconds.
                        ready = yield socket.poll(300, zmq.POLLIN)
                    except zmq.eventloop.future.CancelledError as exc:
                        log.trace(
                            "Loop closed while polling receive socket.", exc_info=True
                        )
                        log.error("Master is unavailable (Connection Cancelled).")
                        send_recv_running = False
                        if not future.done():
                            future.set_result(None)
                    except zmq.ZMQError as exc:
                        log.trace("Receive socket closed while polling.")
                        send_recv_running = False
                        if not future.done():
                            future.set_exception(exc)

                    if ready:
                        try:
                            recv = yield socket.recv()
                            received = True
                        except zmq.eventloop.future.CancelledError as exc:
                            log.trace("Loop closed while receiving.")
                            send_recv_running = False
                            if not future.done():
                                future.set_exception(exc)
                        except zmq.ZMQError as exc:
                            log.trace("Receive socket closed while receiving.")
                            send_recv_running = False
                            if not future.done():
                                future.set_exception(exc)
                        break
                    elif future.done():
                        break

                if future.done():
                    exc = future.exception()
                    if isinstance(exc, SaltReqTimeoutError):
                        log.trace(
                            "Request timed out while waiting for a response. reconnecting."
                        )
                    else:
                        log.trace("The request ended with an error. reconnecting.")
                    # Only reconnect if the client is still active. If close()
                    # was already called externally (context is None), do not
                    # create a new socket/context that would never be cleaned up.
                    _should_reconnect = self.context is not None
                    self._close_zmq_only()
                    if _should_reconnect:
                        self.connect()
                    send_recv_running = False
                elif received:
                    data = salt.payload.loads(recv)
                    if not future.done():
                        future.set_result(data)
        finally:
            if (
                self._send_recv_exit_future is not None
                and not self._send_recv_exit_future.done()
            ):
                self._send_recv_exit_future.set_result(None)
        log.trace("Send and receive coroutine ending %s", socket)


class ZeroMQSocketMonitor:
    __EVENT_MAP = None

    def __init__(self, socket):
        """
        Create ZMQ monitor sockets

        More information:
            http://api.zeromq.org/4-0:zmq-socket-monitor
        """
        self._socket = socket
        self._monitor_socket = self._socket.get_monitor_socket()
        self._monitor_task = None
        self._running = asyncio.Event()

    def start_io_loop(self, io_loop):
        log.trace("Event monitor start!")
        self._running.set()
        self._running_task = salt.utils.asynchronous.aioloop(io_loop).create_task(
            self.consume()
        )

    async def consume(self):
        while self._running.is_set():
            try:
                if await self._monitor_socket.poll():
                    msg = await self._monitor_socket.recv_multipart()
                    self.monitor_callback(msg)
                else:
                    await asyncio.sleep(0.3)
            except zmq.error.ZMQError as exc:
                log.error("ZmqMonitor, %s", exc)
                # We've disconnected just die
                break
            except Exception as exc:  # pylint: disable=broad-except
                log.error("ZmqMonitor, %s", exc)
                break

    def start_poll(self):
        log.trace("Event monitor start!")
        try:
            while self._monitor_socket is not None and self._monitor_socket.poll():
                msg = self._monitor_socket.recv_multipart()
                self.monitor_callback(msg)
        except (AttributeError, zmq.error.ContextTerminated):
            # We cannot log here because we'll get an interrupted system call in trying
            # to flush the logging buffer as we terminate
            pass

    @property
    def event_map(self):
        if ZeroMQSocketMonitor.__EVENT_MAP is None:
            event_map = {}
            for name in dir(zmq):
                if name.startswith("EVENT_"):
                    value = getattr(zmq, name)
                    event_map[value] = name
            ZeroMQSocketMonitor.__EVENT_MAP = event_map
        return ZeroMQSocketMonitor.__EVENT_MAP

    def monitor_callback(self, msg):
        evt = zmq.utils.monitor.parse_monitor_message(msg)
        evt["description"] = self.event_map[evt["event"]]
        log.debug("ZeroMQ event: %s", evt)
        if evt["event"] == zmq.EVENT_MONITOR_STOPPED:
            self.stop()
        elif evt["event"] == zmq.EVENT_DISCONNECTED:
            if (
                hasattr(self, "disconnect_callback")
                and self.disconnect_callback is not None
            ):
                self.disconnect_callback()

    def stop(self):
        if self._socket is None:
            return
        try:
            self._socket.disable_monitor()
        except zmq.Error:
            pass
        if self._monitor_socket is not None:
            try:
                self._monitor_socket.close(0)
            except zmq.Error:
                pass
        self._socket = None
        self._running.clear()
        self._monitor_socket.close()
        self._monitor_socket = None
        log.trace("Event monitor done!")


def _strip_presence_prefix(topic):
    """``topic`` without the announcement prefix, if it carries one.

    The topic map is keyed by the bare digest, so everything that
    looks a topic up has to agree about this.
    """
    prefix = PRESENCE_TOPIC_PREFIX.decode()
    if topic.startswith(prefix):
        return topic[len(prefix) :]
    return topic


def _peer_address(frame):
    """The address a subscription frame arrived from, or ``""``.

    0MQ attaches this to the frame as ``Peer-Address``. It is absent over IPC
    and raises rather than returning None, hence the broad guard -- an address
    is a nicety here, and failing to read one must not cost us the presence
    event the frame represents.
    """
    getter = getattr(frame, "get", None)
    if getter is None:
        return ""
    try:
        return getter("Peer-Address") or ""
    except Exception:  # pylint: disable=broad-except
        return ""


class _Unresolved(Exception):
    """A subscription whose topic did not name anybody, so it was parked.

    Control flow only -- it leaves the per-frame handler without skipping
    the retry and revocation prune that follow it.
    """


class _SubscriberStub:
    """Stand-in for a subscriber connection, for transports that have an id
    but no connection object.

    The presence bookkeeping in ``salt.channel.server`` keys on ``id_`` and
    stores the object in a set, so it needs something hashable and stable per
    subscription — 0MQ pub/sub exposes no connection handle.
    """

    __slots__ = ("id_", "address")

    def __init__(self, id_, address=""):
        self.id_ = id_
        #: Where the subscriber connects from, for parity with the TCP
        #: transport's ``Subscriber.address``. Empty when 0MQ does not report
        #: one, as over IPC.
        self.address = address


class PublishServer(salt.transport.base.DaemonizedPublishServer):
    """
    Encapsulate synchronous operations for a publisher channel
    """

    # Backstop rebuild interval, in seconds, for the subscription topic map
    # (see _topic_to_minion).
    _topic_map_interval = 60
    #: Never rebuild the topic map more often than this. An
    #: ``auto_accept`` storm writes accepted keys continuously, so the
    #: directory mtime moves constantly and would otherwise rebuild per
    #: message
    #: -- a listdir, a stat per minion, and a read for each key that
    #: rotated, on the loop that publishes jobs.
    #: Safe only because a topic that fails to resolve is parked and retried
    #: rather than dropped; see ``_unresolved``.
    _topic_map_min_interval = 1.0
    #: Most unresolved topics to hold for retry. They arrive from
    #: unauthenticated peers, so this cannot be allowed to grow freely --
    #: but it has to be able to hold a whole fleet, because a legitimate
    #: topic parks when a minion subscribes before the master has rebuilt
    #: its map -- an ``auto_accept`` storm can do that to many minions at
    #: once. (A master *restart* does not: the first frame rebuilds from
    #: session files that already exist, so the fleet resolves rather than
    #: parking.) An entry is a prefixed topic -- a 64-character digest
    #: behind an 18-byte prefix -- and an address, so this is single-digit
    #: megabytes at the limit.
    _max_unresolved = 16384
    #: How long a parked topic stays parked. Bounded because a topic an
    #: unauthenticated peer invented resolves on no rebuild ever, so
    #: without a deadline the sweeper would run for the life of the
    #: publish daemon.
    #:
    #: Generous relative to what it covers: a minion cannot compute its
    #: topic before it has authenticated, so parking is not "waiting for
    #: an operator to accept a key", it is a sub-second staleness race
    #: that the first sweep resolves.
    _unresolved_ttl = 60.0

    async_methods = [
        "publish",
    ]
    close_methods = [
        "close",
    ]

    def __init__(
        self,
        opts,
        pub_host=None,
        pub_port=None,
        pub_path=None,
        pull_host=None,
        pull_port=None,
        pull_path=None,
        pull_path_perms=0o600,
        pub_path_perms=0o600,
        started=None,
        secrets=None,
    ):
        self.opts = opts
        self.pub_host = pub_host
        self.pub_port = pub_port
        self.pub_path = pub_path
        if pub_path:
            self.pub_uri = f"ipc://{pub_path}"
        else:
            self.pub_uri = f"tcp://{pub_host}:{pub_port}"
        self.pull_host = pull_host
        self.pull_port = pull_port
        self.pull_path = pull_path
        self.pub_path_perms = pub_path_perms
        self.pull_path_perms = pull_path_perms
        if pull_path:
            self.pull_uri = f"ipc://{pull_path}"
        else:
            self.pull_uri = f"tcp://{pull_host}:{pull_port}"
        self.ctx = None
        self.sock = None
        self.daemon_context = None
        self.daemon_pub_sock = None
        self.daemon_pull_sock = None
        self.daemon_monitor = None
        self.secrets = secrets
        # Subscription-derived presence (see _subscription_presence):
        # announcement topic -> minion_id, and topic -> subscriber stub.
        self._topic_map = {}
        self._topic_map_stamp = -1
        self._topic_map_built = 0.0
        #: Bumped on every rebuild, so the unresolved sweep can tell whether
        #: there is any point running again.
        self._topic_map_generation = 0
        #: The timer task that retries parked subscriptions, or None.
        self._sweeper = None
        self._unresolved_generation = -1
        #: Subscriptions whose topic did not resolve when it arrived, kept
        #: so a later rebuild can still name them. libzmq delivers each
        #: SUBSCRIBE exactly once, so without this a minion that subscribed
        #: whose accepted key the master had not yet seen -- the rebuild is
        #: debounced, a network filesystem can lag, a listing can fail --
        #: would be
        #: invisible for the life of its connection, with the record
        #: staying settled so nothing fell back either.
        #: topic -> (address, deadline), oldest first. Eviction takes
        #: from the new end; see ``_park_unresolved``.
        self._unresolved = collections.OrderedDict()
        #: Whether the last topic-map rebuild saw the directories, and the
        #: generation ``_prune_revoked`` last acted on.
        self._topic_map_complete = False
        self._pruned_generation = -1
        self._readmitted_generation = -1
        #: When the directories were last stat-ed, as opposed to when the
        #: map was last rebuilt; see ``_topic_to_minion``.
        self._topic_map_checked = 0.0
        self._remove_presence_callback = None
        self._presence_callback = None
        self._revocation_watch = None
        #: Subscribers retracted by ``_prune_revoked`` whose subscription
        #: is still live, keyed by topic; see ``_readmit_restored``.
        self._retracted = {}
        self._present = {}
        self._presence_task = None
        if started is None:
            self.started = multiprocessing.Event()
        else:
            self.started = started

    @classmethod
    def support_ssl(cls):
        # Required from DaemonizedPublishServer
        return False

    def topic_support(self):
        # Required from DaemonizedPublishServer
        return self.opts.get("zmq_filtering", False)

    def __repr__(self):
        return f"<PublishServer pub_uri={self.pub_uri} pull_uri={self.pull_uri} at {hex(id(self))}>"

    def __setstate__(self, state):
        self.__init__(**state)

    def __getstate__(self):
        return {
            "opts": self.opts,
            "pub_host": self.pub_host,
            "pub_port": self.pub_port,
            "pub_path": self.pub_path,
            "pull_host": self.pull_host,
            "pull_port": self.pull_port,
            "pull_path": self.pull_path,
            "pub_path_perms": self.pub_path_perms,
            "pull_path_perms": self.pull_path_perms,
            "started": self.started,
            "secrets": getattr(self, "secrets", None),
        }

    def publish_daemon(
        self,
        publish_payload,
        presence_callback=None,
        remove_presence_callback=None,
        secrets=None,
        started=None,
        on_start=None,
    ):
        """
        This method represents the Publish Daemon process. It is intended to be
        run in a thread or process as it creates and runs its own ioloop.
        """
        print("publish_daemon starting!")
        if started is not None:
            self.started = started
        if secrets is not None:
            self.secrets = secrets
        elif not hasattr(self, "secrets"):
            self.secrets = self.opts.get("secrets")
        io_loop = salt.utils.asynchronous.aioloop(tornado.ioloop.IOLoop())

        if on_start is not None:
            # Run on the daemon's own loop, once it exists: the caller has
            # none of its own, and anything it needs to schedule has to be
            # scheduled here or not at all.
            io_loop.call_soon(on_start)
        publisher_task = io_loop.create_task(
            self.publisher(
                publish_payload,
                presence_callback=presence_callback,
                remove_presence_callback=remove_presence_callback,
                io_loop=io_loop,
            ),
            name="PublishServer.publisher",
        )
        publisher_task._log_destroy_pending = False
        try:
            print("publish_daemon running io_loop!")
            io_loop.run_forever()
        finally:
            print("publish_daemon closing!")
            self.close()

    def _get_sockets(self, context, io_loop, subscriptions=False):
        if subscriptions:
            # XPUB rather than PUB: an XPUB publisher receives the SUBSCRIBE /
            # UNSUBSCRIBE messages its subscribers send, which is the only
            # per-subscriber signal 0MQ pub/sub offers. Subscribers announce
            # themselves on PRESENCE_TOPIC_PREFIX + an assigned digest, so those
            # carry identity and give this transport the same id-keyed presence
            # the TCP transport has. XPUB is otherwise a superset of PUB for
            # publishing; subscribers see no difference.
            pub_sock = context.socket(zmq.XPUB)
            # Deliberately *not* XPUB_VERBOSE. libzmq refcounts subscriptions
            # per topic and delivers the first subscribe and the last
            # unsubscribe for each, which for an identity-bearing topic -- one
            # subscriber per topic -- is exactly one presence edge in each
            # direction, including when a minion reconnects over its own
            # not-yet-reaped connection. XPUB_VERBOSE would add a message
            # per duplicate subscribe with no extra information.
            #
            # It would not, however, be the difference between a bounded
            # and an unbounded pending queue: that queue is a FIFO of
            # notification events, not a set of live topics, and
            # non-verbose does not bound it. Measured on libzmq 4.3.5,
            # 400k subscribe/unsubscribe toggles of one topic with
            # verbose OFF grew the publisher by ~160 MB -- every toggle
            # is a first-add and a last-remove, so every one notifies.
            # See the hazard note in ``_subscription_presence``.
            #
            # An XPUB, unlike a PUB, keeps whatever its subscribers send
            # upstream instead of discarding it, and 0MQ places no limit on
            # a message by default. Without this an unauthenticated peer
            # that can reach the publish port could hand the publish daemon
            # frames of any size and watch its memory follow. Subscription
            # messages are tens of bytes; the cap is generous beside that
            # and far below anything worth worrying about.
            pub_sock.setsockopt(zmq.MAXMSGSIZE, _MAX_SUBSCRIPTION_MSG)
        else:
            # Only ask for subscription messages when something is going to
            # read them: libzmq drains subscription frames off the inbound
            # pipes as they arrive and holds them in a pending queue that
            # grows until the application recv()s it. The ``RCVHWM`` set
            # below bounds the pipes, not that queue, so an XPUB nobody
            # drains accumulates for the life of the master.
            pub_sock = context.socket(zmq.PUB)
        monitor = ZeroMQSocketMonitor(pub_sock)
        monitor.start_io_loop(io_loop)
        _set_tcp_keepalive(pub_sock, self.opts)
        _set_zmq_heartbeat(pub_sock, self.opts)
        self.dpub_sock = pub_sock  # = zmq.eventloop.zmqstream.ZMQStream(pub_sock)
        # if 2.1 >= zmq < 3.0, we only have one HWM setting
        try:
            pub_sock.setsockopt(zmq.HWM, self.opts.get("pub_hwm", 1000))
        # in zmq >= 3.0, there are separate send and receive HWM settings
        except (AttributeError, zmq.error.ZMQError):
            # Set the High Water Marks. For more information on HWM, see:
            # http://api.zeromq.org/4-1:zmq-setsockopt
            pub_sock.setsockopt(zmq.SNDHWM, self.opts.get("pub_hwm", 1000))
            pub_sock.setsockopt(zmq.RCVHWM, self.opts.get("pub_hwm", 1000))
        if self.opts["ipv6"] is True and hasattr(zmq, "IPV4ONLY"):
            # IPv6 sockets work for both IPv6 and IPv4 addresses
            pub_sock.setsockopt(zmq.IPV4ONLY, 0)

        pub_sock.setsockopt(zmq.BACKLOG, self.opts.get("zmq_backlog", 1000))
        pub_sock.setsockopt(zmq.LINGER, 1)
        # Prepare minion pull socket
        pull_sock = context.socket(zmq.PULL)
        pull_sock.setsockopt(zmq.LINGER, 1)
        # pull_sock = zmq.eventloop.zmqstream.ZMQStream(pull_sock)
        pull_sock.setsockopt(zmq.LINGER, 1)
        salt.utils.zeromq.check_ipc_path_max_len(self.pull_uri)
        # Start the minion command publisher
        # Securely create socket
        with salt.utils.files.set_umask(0o177):
            log.info("Starting the Salt Publisher on %s", self.pub_uri)
            pub_sock.bind(self.pub_uri)
            if self.pub_path:
                os.chmod(  # nosec
                    self.pub_path,
                    self.pub_path_perms,
                )
            log.info("Starting the Salt Puller on %s", self.pull_uri)
            pull_sock.bind(self.pull_uri)
            if self.pull_path:
                os.chmod(  # nosec
                    self.pull_path,
                    self.pull_path_perms,
                )
        return pull_sock, pub_sock, monitor

    async def publisher(
        self,
        publish_payload,
        presence_callback=None,
        remove_presence_callback=None,
        io_loop=None,
    ):
        print("publisher task started!")
        if io_loop is None:
            io_loop = tornado.ioloop.IOLoop.current()
        # Imported here rather than at module scope: salt.utils.channel imports
        # salt.master, which imports its way back into the transports. Import
        # the name, not the package -- ``import salt.utils.channel`` would bind
        # ``salt`` as a local for the whole function.
        from salt.utils.channel import transport_provides_presence

        # The same predicate salt.channel.server.PubServerChannel.factory and
        # salt.master.Maintenance use to decide who owns presence, so the
        # subscription reader runs exactly when the publish server is the one
        # expected to report it.
        presence = presence_callback is not None and transport_provides_presence(
            self.opts
        )
        self.daemon_context = zmq.asyncio.Context()
        (
            self.daemon_pull_sock,
            self.daemon_pub_sock,
            self.daemon_monitor,
        ) = self._get_sockets(self.daemon_context, io_loop, subscriptions=presence)
        print("publisher sockets created, setting started event!")
        if presence:
            self._presence_task = io_loop.create_task(
                self._subscription_presence(
                    presence_callback, remove_presence_callback
                ),
                name="PublishServer.subscription_presence",
            )
            self._presence_task._log_destroy_pending = False
        self.started.set()
        while True:
            try:
                package = await self.daemon_pull_sock.recv()
                await publish_payload(package)
            except Exception as exc:  # pylint: disable=broad-except
                log.error(
                    "Exception in publisher %s %s",
                    self.pull_uri,
                    exc,
                    exc_info_on_loglevel=logging.DEBUG,
                )

    def _accepted_keys_dir(self):
        """Directory holding the accepted minion keys.

        Cluster masters keep the shared key set in ``cluster_pki_dir``;
        this is the same branch ``salt.key.Key`` and
        ``salt.master.Maintenance`` make.
        """
        if self.opts.get("cluster_id", None):
            pki_dir = self.opts.get("cluster_pki_dir") or self.opts["pki_dir"]
        else:
            pki_dir = self.opts["pki_dir"]
        return os.path.join(pki_dir, "minions")

    def _read_topic_map(self):
        """Build announcement-topic -> minion_id over the accepted keys.

        The topic is an HMAC of the minion id under a secret only this
        master holds (see :func:`salt.utils.presence.topic_for`), so
        producing one requires either having been handed it at
        authentication or holding that secret. A plain hash of the id
        would not: ids are usually hostnames, and anything able to reach
        the publish port could then both claim presence for a minion and
        withdraw it for one really connected.

        Driven entirely by the accepted keys. There is no per-minion file
        to read and no session directory involved -- the latter mattering
        because ``ReqServerChannel`` creates ``<cachedir>/sessions/<id>``
        from the id in a request, checked for shape and nothing else, so
        anything able to reach the request port can create entries there.
        Nothing an unauthenticated peer can write feeds this map or
        triggers its rebuild any more.
        """
        accepted = self._accepted_keys_dir()
        try:
            ids = os.listdir(accepted)
        except OSError as exc:
            log.debug("Unable to list accepted keys in %s: %s", accepted, exc)
            return {}, False
        secret = salt.utils.presence.presence_secret(self.opts)
        if secret is None:
            log.error("No presence secret; no subscriber can be named")
            return {}, False
        topics = {}
        for id_ in ids:
            if id_.startswith("."):
                continue
            topics[
                hmac.new(
                    secret, salt.utils.stringutils.to_bytes(id_), hashlib.sha256
                ).hexdigest()
            ] = id_
        return topics, True

    def _topic_to_minion(self, topic):
        """Resolve an announcement topic to a minion id.

        The only topic that names a subscriber is
        ``PRESENCE_TOPIC_PREFIX`` + the digest the master assigned. The bare
        ``sha1(id)`` a minion subscribes to for delivery under
        ``zmq_filtering`` is deliberately *not* accepted: it is derived
        from the id alone, so honouring it would let anything able to
        reach the publish port name itself any accepted minion, and
        cancel the subscription of one that is really connected.

        That makes ``zmq_filtering`` irrelevant to presence, which is the
        tidier arrangement anyway -- presence is enabled by one option and
        only by that option. The cost is that a minion too old to announce
        itself cannot be seen at all; previously ``zmq_filtering`` covered
        those, at the price of a forgeable topic.

        Rebuilding the map costs one ``listdir`` and an HMAC per
        accepted key -- no per-minion file is read at all -- and it is
        driven by
        unauthenticated remote input -- anything that can reach the
        publish port can send subscriptions -- so it must not happen per
        message. The accepted-keys directory's mtime is the trigger
        instead.

        Two intervals bound it from either side. A rebuild happens at most
        once per ``_topic_map_min_interval``, because a busy master
        accepts keys continuously and the trigger alone would fire
        on nearly every message. It happens at least once per
        ``_topic_map_interval``, as a backstop for filesystems whose
        timestamp granularity could hide a change, which also bounds how
        long a departed minion keeps resolving.

        Debouncing is only safe because a topic that fails to resolve is
        parked rather than dropped -- libzmq delivers each SUBSCRIBE
        exactly once, so a miss during the debounce window would otherwise
        lose that minion for the life of its connection. See
        ``_park_unresolved``.
        """
        self._maybe_rebuild_topic_map()
        return self._resolve(topic)

    def _maybe_rebuild_topic_map(self, force=False):
        """Rebuild the topic map if anything can have changed the answer.

        ``force`` skips the debounce and the stamp comparison; it is for
        the periodic revocation check, which has to run on a master that
        is seeing no subscription traffic at all.
        """
        now = time.monotonic()
        since_built = now - self._topic_map_built
        # The clock first, the syscalls second. This runs per subscription
        # frame, and the frames are unauthenticated: stat-ing before the
        # debounce has been cleared spends a syscall per frame on an
        # answer the debounce was going to throw away. The reader's drain
        # rate is the only thing bounding the XPUB pending deque, which
        # libzmq does not cap, so per-frame cost here is a memory-growth
        # lever and not merely a CPU one.
        if not force and now - self._topic_map_checked < self._topic_map_min_interval:
            # Inside the debounce nothing can change the answer, so this
            # frame pays for no syscalls at all.
            #
            # Gated on when the directories were last *checked*, not when
            # the map was last rebuilt. Those differ whenever the stamp is
            # unchanged -- the steady state -- and gating on the rebuild
            # meant ``since_built`` stayed above the interval forever, so
            # every frame thereafter paid both stats. That is work
            # proportional to an unauthenticated peer's frame rate, which
            # is the one thing this loop must not have.
            return
        self._topic_map_checked = now
        try:
            # One directory now: the accepted keys are the only input,
            # and unlike the session directory nothing an unauthenticated
            # peer can reach is able to touch it.
            stamp = os.stat(self._accepted_keys_dir()).st_mtime_ns
        except OSError:
            stamp = None
        if (
            force
            or stamp != self._topic_map_stamp
            or since_built >= self._topic_map_interval
        ):
            topics, complete = self._read_topic_map()
            self._topic_map = topics
            self._topic_map_built = now
            self._topic_map_generation += 1
            # Whether this map is a real picture of the directories or the
            # empty one a failed listdir produces. ``_prune_revoked`` must
            # not act on the latter: it would read as "every key has been
            # revoked" and retract the entire fleet.
            self._topic_map_complete = complete
            # Only remember the directory state if the read actually saw it.
            # Caching the stamp after a failed listdir would pin an empty map
            # in place until the directory changed again or the backstop
            # fired, and every subscription arriving in that window would be
            # dropped -- permanently, because libzmq delivers each SUBSCRIBE
            # exactly once and the record goes on looking settled.
            self._topic_map_stamp = stamp if complete else None

    def _resolve(self, topic):
        """Look a wire topic up in the map as it currently stands.

        The prefix is *required*, not merely stripped:
        ``_strip_presence_prefix`` is a no-op on a topic that does not
        carry it, so stripping unconditionally would resolve a bare digest
        too -- and disagree with ``_could_name_a_minion``, which does
        require it. The two deciding differently is how a topic gets
        parked forever, or named when it should not be.
        """
        if not topic.startswith(PRESENCE_TOPIC_PREFIX.decode()):
            return None
        return self._topic_map.get(_strip_presence_prefix(topic))

    @staticmethod
    def _could_name_a_minion(topic):
        """Whether ``topic`` is even the right shape to resolve later.

        Every topic this reader can name is the hex HMAC produced by
        ``salt.utils.presence.topic_for``, behind ``PRESENCE_TOPIC_PREFIX``.
        Anything else
        will never resolve however long it is kept -- and keeping it is
        exactly what an unauthenticated peer would want, since the parked
        set is a fixed size and shared with the minions waiting to be named.
        """
        if not topic.startswith(PRESENCE_TOPIC_PREFIX.decode()):
            return False
        topic = _strip_presence_prefix(topic)
        return len(topic) == _TOPIC_HEX_LEN and all(
            c in "0123456789abcdef" for c in topic
        )

    def _park_unresolved(self, topic, address, deadline=None):
        """Remember a subscription whose topic did not resolve.

        Parking starts the sweeper, which is what eventually retries
        this. It deliberately does *not* invalidate the topic map: the
        topics that park are the ones an unauthenticated peer invented, so
        rebuilding on a park would let it drive a ``listdir`` and a
        fleet-sized dict per frame, on the loop that publishes every job.

        ``deadline`` carries an existing entry's expiry across a re-park.
        A re-park that restamped it would be refreshed on every sweep
        tick, so an entry whose presence callback keeps failing would
        never expire and the sweeper would never stop -- which is the one
        thing ``_unresolved_ttl`` exists to guarantee.

        Eviction takes the *newest* entry, which is the opposite of the
        usual cache policy and is the whole defence here. The parked set
        is fed by unauthenticated input. A legitimate park is always
        older than whatever arrives after it: it happens when a minion
        subscribes inside the rebuild debounce, and it clears on the next
        sweep a second later. So under oldest-out a peer that can reach
        the publish port evicts real minions by flooding -- and libzmq
        never redelivers a SUBSCRIBE, so each one is invisible for the
        life of its connection. Newest-out drops the flooder's current
        frame instead and leaves the minion that has been waiting.

        Junk cannot wedge the set the way it could before
        ``_unresolved_ttl`` existed; it expires on its own.

        Deliberately *not* bucketed per source address. That sounds like
        the tighter rule and is the wrong one here: minions behind one
        NAT share a source address -- the publish server sees the
        gateway's, which is the entire situation this feature exists for
        -- so a per-address cap truncates exactly the fleet it is meant
        to protect, and does so silently.
        """
        if not self._could_name_a_minion(topic):
            return
        now = time.monotonic()
        if deadline is None:
            deadline = now + self._unresolved_ttl
        self._unresolved.pop(topic, None)
        self._unresolved[topic] = (address, deadline)
        while len(self._unresolved) > self._max_unresolved:
            # The newest *other* entry, never the one just inserted.
            # ``popitem(last=True)`` takes the arrival itself, so a peer
            # that fills the table first -- and it chooses when to send --
            # gets every subsequent legitimate park discarded on arrival.
            # libzmq never redelivers a SUBSCRIBE, so each of those
            # minions is invisible for the life of its connection.
            victim = next((t for t in reversed(self._unresolved) if t != topic), None)
            if victim is None:
                break
            self._forget_unresolved(victim)

    def _prune_revoked(self, remove_presence_callback):
        """Retract subscribers whose key has been revoked.

        The accepted-key check in ``_read_topic_map`` only runs on the
        SUBSCRIBE edge, so without this a minion whose key is revoked
        while it is connected stays in ``_present`` -- and so in
        ``connected_ids()`` and in ``max_minions`` -- until its TCP
        connection drops, which an operator revoking a key has no way to
        force. Address matching, which this replaces, did not have that
        hole: ``salt-key -d`` flushes the grains cache the matching reads.

        Keyed on the *id*, not on whether the topic still resolves.
        Those are not the same question, and only the first one means
        revocation. The topic no longer moves while a minion is
        connected -- it is assigned once from a secret that does not
        rotate -- but the map can still come back empty for reasons that
        are not revocations at all: a failed listing, an unreadable
        secret. Retracting on "the topic stopped resolving" would drop
        the whole fleet on any of those, reporting connected, reachable
        minions as absent, which is the bug this feature exists to fix.

        Only after a rebuild, and only a rebuild that actually saw the
        directories: a failed ``listdir`` yields an empty map, and acting
        on that would retract the whole fleet at once.
        """
        if not self._topic_map_complete:
            return
        if self._pruned_generation == self._topic_map_generation:
            return
        self._pruned_generation = self._topic_map_generation
        accepted = self._accepted_keys_dir()
        if not os.path.isdir(accepted):
            # The directory itself is gone or unreadable. Every lookup
            # below would say "revoked" and retract the whole fleet on
            # what is really a filesystem problem.
            log.warning(
                "Accepted-keys directory %s is not readable; not retracting"
                " any minion's presence",
                accepted,
            )
            return
        for topic in list(self._present):
            stub = self._present.get(topic)
            id_ = getattr(stub, "id_", None)
            if id_ is None:
                continue
            try:
                os.stat(os.path.join(accepted, id_))
                continue
            except FileNotFoundError:
                pass
            except OSError as exc:
                # Deliberately ``os.stat`` and not ``os.path.exists``:
                # the latter swallows every OSError and returns False, so
                # a directory that lists but whose children cannot be
                # stat-ed -- an NFS EACCES or ESTALE blip, EMFILE, a
                # permissions change -- would read as "every key revoked"
                # and retract the entire fleet. There is no recovery path
                # from that: the stubs are gone and libzmq will not
                # redeliver the subscriptions. Only ENOENT is evidence of
                # revocation.
                log.warning(
                    "Cannot tell whether %s still holds an accepted key"
                    " (%s); leaving its presence alone",
                    id_,
                    exc,
                )
                continue
            log.info(
                "Minion %s no longer holds an accepted key; retracting its"
                " presence (topic %s)",
                id_,
                topic,
            )
            if stub is not None and remove_presence_callback is not None:
                try:
                    remove_presence_callback(stub)
                except Exception as exc:  # pylint: disable=broad-except
                    log.error(
                        "Exception retracting presence for topic %s: %s",
                        topic,
                        exc,
                        exc_info_on_loglevel=logging.DEBUG,
                    )
                    # Left in place so the next rebuild tries again,
                    # rather than dropped here and leaked in the channel.
                    continue
            # Kept, not forgotten. libzmq delivers each SUBSCRIBE exactly
            # once and ``announce_presence`` short-circuits on an
            # unchanged topic, so a minion that stays connected across
            # ``salt-key -d`` then ``salt-key -a`` sends nothing further
            # -- and without this it is absent until it restarts, which
            # may be never. Re-accepting a key has to be able to undo a
            # retraction.
            self._retracted[topic] = self._present.pop(topic)

    def _readmit_restored(self):
        """Re-admit subscribers whose key has been accepted again.

        The counterpart to ``_prune_revoked``: the subscription is still
        live on the socket -- nothing about a key being removed and
        restored reaches the subscriber -- so the only thing that changed
        is whether the master is willing to name it.

        Bounded by ``_present``, which is fleet-bounded, not by anything
        an unauthenticated peer supplies: a topic only ever enters here
        by having been named and then retracted.

        Gated on the topic-map generation, like ``_prune_revoked``.
        Without that this ran per *frame*, costing a ``stat`` for every
        retracted entry -- and ``_retracted`` is fleet-sized after a
        ``salt-key -D``, with entries persisting until each minion
        unsubscribes, which a revoked one has no reason to do. That made
        it work proportional to the fleet for every frame an
        unauthenticated peer chose to send, on the loop that publishes
        every job. Nothing can change the answer between rebuilds
        anyway: the accepted keys are the only input.
        """
        if not self._retracted or not self._topic_map_complete:
            return
        if self._readmitted_generation == self._topic_map_generation:
            return
        self._readmitted_generation = self._topic_map_generation
        accepted = self._accepted_keys_dir()
        if not os.path.isdir(accepted):
            return
        for topic, stub in list(self._retracted.items()):
            try:
                os.stat(os.path.join(accepted, stub.id_))
            except OSError:
                continue
            log.info(
                "Minion %s holds an accepted key again; restoring its"
                " presence (topic %s)",
                stub.id_,
                topic,
            )
            del self._retracted[topic]
            self._present[topic] = stub
            yield stub

    def _forget_unresolved(self, topic):
        """Stop tracking a parked topic."""
        self._unresolved.pop(topic, None)

    def _expire_unresolved(self):
        """Drop parked topics that have outlived ``_unresolved_ttl``.

        This is what lets the sweeper stop. A topic invented by an
        unauthenticated peer resolves on no rebuild ever, so without an
        expiry the loop below would run for the life of the publish
        daemon.
        """
        now = time.monotonic()
        for topic, (_, deadline) in list(self._unresolved.items()):
            if deadline <= now:
                log.debug("Giving up on unresolved subscription topic %s", topic)
                self._forget_unresolved(topic)

    async def _watch_revocations(self, remove_presence_callback):
        """Retract revoked minions on a timer, not only on traffic.

        ``_prune_revoked`` is otherwise reached from two places that both
        need something to be happening: the unresolved sweeper, which only
        exists while something is parked, and the foot of the per-frame
        subscription loop. A master in steady state has neither -- no
        parked topics and no subscription frames, because libzmq sends one
        SUBSCRIBE per topic and nothing repeats it.

        That is precisely the state an operator is in when they run
        ``salt-key -d``. Without this the revoked minion would stay in
        ``connected_ids()`` and in ``max_minions`` until something
        unrelated happened to arrive. ``salt-key -d`` does rotate the AES
        key, but a re-authentication produces no new SUBSCRIBE unless the
        *session* key moved too, so it cannot be relied on to wake this up.

        One forced rebuild per ``_topic_map_interval``, which is the same
        cost the backstop in ``_maybe_rebuild_topic_map`` already pays on
        a busy master.
        """
        try:
            while True:
                await asyncio.sleep(self._topic_map_interval)
                try:
                    self._maybe_rebuild_topic_map(force=True)
                    self._prune_revoked(remove_presence_callback)
                    for stub in self._readmit_restored():
                        await self._presence_callback(stub, None)
                except Exception:  # pylint: disable=broad-except
                    log.error("Revocation check failed", exc_info=True)
        except asyncio.CancelledError:
            raise

    def _ensure_sweeper(self, presence_callback):
        """Start the retry sweeper if anything is waiting for it."""
        if self._sweeper is not None or not self._unresolved:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._sweeper = loop.create_task(
            self._sweep_unresolved(presence_callback),
            name="PublishServer.sweep_unresolved",
        )
        self._sweeper._log_destroy_pending = False

    async def _sweep_unresolved(self, presence_callback):
        """Retry parked subscriptions on a timer until none are left.

        Time-driven rather than frame-driven, because the subscription
        that needs retrying is often the *last* one to arrive -- the tail
        of an ``auto_accept`` storm, or a lone minion on a quiet fleet --
        and nothing follows it. libzmq delivers each SUBSCRIBE exactly
        once, so a parked topic that is never swept is a minion invisible
        for the life of its connection.

        One rebuild per interval at most, however many topics are parked
        and however fast they arrive, which is what keeps this from being
        the amplifier that parking-forces-a-rebuild was.
        """
        try:
            while self._unresolved:
                await asyncio.sleep(self._topic_map_min_interval)
                self._expire_unresolved()
                if not self._unresolved:
                    break
                # Deliberately NOT forcing a rebuild. Forcing cost one
                # full ``listdir`` and an HMAC per accepted key per tick
                # for the whole TTL -- around sixty O(fleet) rebuilds
                # bought with a single well-shaped frame from an
                # unauthenticated peer, on the loop that publishes every
                # job. The ordinary trigger already covers what parking
                # waits for: a topic parks because the session file was
                # written after the last rebuild, and that write changes
                # the directory mtime, so the next call rebuilds anyway.
                # Timestamp granularity hiding it is what the
                # ``_topic_map_interval`` backstop is for.
                self._topic_to_minion(next(iter(self._unresolved)))
                await self._retry_unresolved(presence_callback)
                self._prune_revoked(self._remove_presence_callback)
                if self._presence_callback is not None:
                    for stub in self._readmit_restored():
                        await self._presence_callback(stub, None)
        except asyncio.CancelledError:
            raise
        except Exception:  # pylint: disable=broad-except
            log.error("Unresolved-subscription sweeper failed", exc_info=True)
        finally:
            self._sweeper = None

    async def _retry_unresolved(self, presence_callback):
        """Name any parked subscription the topic map can now resolve.

        Only worth doing when the map has actually been rebuilt: nothing
        else can change the answer, and this runs after every
        subscription-shaped frame. Resolving against ``_topic_map``
        directly rather than through ``_topic_to_minion`` keeps it to one
        dict lookup per entry -- the latter would ``stat`` the key
        directory once per parked topic, which an unauthenticated peer
        could turn into thousands of syscalls per message on the loop that
        publishes every job.
        """
        if not self._unresolved:
            return
        if self._unresolved_generation == self._topic_map_generation:
            return
        self._unresolved_generation = self._topic_map_generation
        for topic, (address, deadline) in list(self._unresolved.items()):
            minion_id = self._resolve(topic)
            if minion_id is None:
                continue
            self._forget_unresolved(topic)
            if topic in self._present:
                continue
            stub = self._present.setdefault(topic, _SubscriberStub(minion_id, address))
            log.debug("Subscription topic %s resolved on retry", topic)
            try:
                await presence_callback(stub, None)
            except Exception as exc:  # pylint: disable=broad-except
                # Same treatment as the main loop: undo the stub and put the
                # topic back, or this retry has consumed the last chance the
                # subscription had. Per topic, so one failure does not abandon
                # the rest of the sweep -- and they would wait for the next
                # rebuild, since the generation has already been advanced.
                log.error(
                    "Exception retrying presence for topic %s: %s",
                    topic,
                    exc,
                    exc_info_on_loglevel=logging.DEBUG,
                )
                self._present.pop(topic, None)
                # The original deadline, not a fresh one: see
                # ``_park_unresolved``. A callback that keeps failing
                # would otherwise hold the sweeper open forever.
                self._park_unresolved(topic, address, deadline=deadline)
                self._ensure_sweeper(presence_callback)

    @staticmethod
    def _retire_presence(presence_callback):
        """Tell the channel behind the callback to stop recording presence.

        The reader cannot be restarted, so once it stops the connected set
        is frozen. The channel keeps a heartbeat running independently of
        this coroutine, and it would go on republishing that frozen set as
        current forever -- ``STALE_AFTER`` is no defence when the component
        still running is the one stamping the record. Retiring it removes
        the record, so readers fall back at once.
        """
        owner = getattr(presence_callback, "__self__", None)
        stop = getattr(owner, "stop_recording_presence", None)
        if stop is None:
            return
        try:
            stop()
        except Exception:  # pylint: disable=broad-except
            log.error("Unable to retire the presence record", exc_info=True)

    async def _subscription_presence(self, presence_callback, remove_presence_callback):
        r"""Turn XPUB subscription traffic into presence events.

        This is the 0MQ counterpart of the TCP transport's per-connection
        presence callbacks. A SUBSCRIBE frame is ``b"\x01" + topic`` and an
        UNSUBSCRIBE is ``b"\x00" + topic``; libzmq synthesises the
        unsubscribe when a subscriber disconnects, which is what makes a
        dropped minion observable.

        Every role that announces itself is visible, syndics included. A
        subscriber too old to send the announcement topic is *not* seen:
        the bare ``sha1(id)`` a ``zmq_filtering`` minion subscribes to for
        delivery is deliberately refused, because it is derived from the
        id alone and so names a subscriber without proving anything. A
        partly-upgraded fleet therefore under-reports, which the option's
        documentation leads with.

        The identity is proved rather than asserted. The topic is
        assigned by the master, derived from a secret of its own that no
        minion holds, and handed to that minion inside the encrypted part
        of its auth reply -- so producing one means either having been
        given it or holding the master's secret. The map is built from
        the accepted keys alone, so revoking a key removes the topic, and
        a minion already connected under it is retracted at the next
        check.

        What that does *not* cover, and the reason presence from this
        transport is still a reporting aid rather than an access-control
        input:

        - *A compromised minion* can announce itself, which is simply what
          it is entitled to do.
        - *An on-path observer* can see a subscription frame and replay
          it, claiming presence for that minion -- or cancel it, since
          cancelling only requires naming the topic, and libzmq forwards a
          cancel even for a topic with no subscribers (checked against the
          4.3.5 source: ``xpub_t::xread_activated`` notifies unless
          ``rm_result == values_remain``, and ``generic_mtrie_t::rm``
          returns ``not_found`` for a topic it does not hold). The real
          subscriber stays subscribed and keeps receiving jobs, so nothing
          else looks wrong. ZeroMQ without CURVE concedes on-path
          attackers regardless.

        - *How cheap this is.* Both of the above need nothing more than a
          stock ``zmq.XSUB`` socket. The master's XPUB leaves
          ``ZMQ_ONLY_FIRST_SUBSCRIBE`` at its default of false, and
          ``xpub_t::xread_activated`` then sets ``_process_subscribe`` for
          *every* part of an upstream multipart message -- so each part
          that looks like a subscription is applied to the trie and handed
          up, not just the first. The sender sets the same option on its
          own socket for the opposite reason: to stop *its* XSUB
          swallowing the continuation parts as local subscribe commands
          before they reach the wire.

          There is no way to tell them apart. libzmq pushes real
          notifications to the application with their flags cleared, and it
          does the same to a continuation part that happens to be
          subscription-shaped, so even the MORE bit does not separate them:
          sending ``[b"payload", b"\x01junk", b"\x00" + victim_topic]``
          delivers three frames of which the last two are indistinguishable
          from genuine traffic. An earlier version of this reader tried to
          drop continuation parts and was defeated by exactly that; see
          ``test_a_real_peer_can_forge_a_subscription_frame``, which pins
          the behaviour so nobody tries again without measuring first.

          A forged cancel is permanent, not transient: libzmq delivers
          each SUBSCRIBE exactly once, so there is no later frame from
          the victim to put it back, and it stays missing for the life of
          its connection. Knowing the topic takes reading it off the
          wire, which ZMTP carries in the clear absent curve or a tunnel.

        - *Cost.* Each toggle is cheap to send and not cheap to handle. It
          costs a map lookup here, and with ``presence_events`` on it also
          costs a ``salt/presence/change`` event, plus a share of the
          whole-fleet ``salt/presence/present`` that
          ``PubServerChannel._fire_present_event`` coalesces to at most one
          a second -- on the same ioloop that publishes every job. The
          XPUB queue those arrive on is a deque libzmq grows without bound
          (``RCVHWM`` bounds the pipes feeding it, not the deque), so a
          sender that outpaces this reader grows the publish daemon's memory
          rather than being throttled; ``ZMQ_MAXMSGSIZE`` caps how big any
          one of them can be. Toggling an *offline* accepted minion's topic
          is the cheapest way to drive both, since libzmq notifies on the
          first subscribe and last unsubscribe and an offline minion holds
          neither.

          Per-message handling is a map lookup, and the shape filter runs
          before it so an invented topic never reaches the resolve at all.
          Inside the debounce window the lookup costs no syscalls either;
          the ``stat`` that drives the rebuild sits behind the
          clock check for that reason, since this reader's drain rate is
          what bounds the unbounded deque described above.

          The map itself is rebuilt at
          most once a second and at least once a minute, which is what keeps
          a continuous ``auto_accept`` storm from turning each subscription
          into a ``listdir`` and a dict the size of the fleet. A rebuild is
          still O(fleet), and the unresolved sweep that follows one is
          O(parked); the point is that neither is per message. Do not add
          per-message work to this loop without reconsidering that -- the
          input is unauthenticated, so anything proportional to anything
          here is someone else's lever on the loop that publishes jobs.

        Closing any of these would take authenticated subscriptions, which
        0MQ pub/sub does not have. Treat presence from this transport as a
        reporting aid, not as an access-control input, and do not expose the
        publish port to anything you would not let publish.
        """
        drain = False
        # The sweeper runs outside this call and also prunes, so it needs
        # the removal callback too.
        self._remove_presence_callback = remove_presence_callback
        self._presence_callback = presence_callback
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            self._revocation_watch = loop.create_task(
                self._watch_revocations(remove_presence_callback),
                name="PublishServer.watch_revocations",
            )
            self._revocation_watch._log_destroy_pending = False
        try:
            drain = await self._subscription_presence_loop(
                presence_callback, remove_presence_callback
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # pylint: disable=broad-except
            # Nothing below the per-frame handler is expected to escape, but
            # if it does the socket is still an XPUB that is still being
            # published on, and leaving it unread is the unbounded-growth
            # problem rather than merely a lost feature.
            log.error(
                "Subscription reader for %s failed unexpectedly",
                self.pub_uri,
                exc_info=True,
            )
            drain = True
        finally:
            # Covers both ways out below and anything unexpected escaping
            # the loop. Cancellation lands here too, where it is harmless:
            # the publish server is shutting down regardless.
            if self._sweeper is not None:
                self._sweeper.cancel()
                self._sweeper = None
            if self._revocation_watch is not None:
                self._revocation_watch.cancel()
                self._revocation_watch = None
            self._retire_presence(presence_callback)
        if drain:
            await self._drain_subscriptions()

    async def _drain_subscriptions(self):
        """Read and discard, after presence has been given up on.

        The socket is still an XPUB and is still being published on, so
        libzmq goes on moving subscription traffic off the inbound pipes
        into a queue it never bounds -- ``RCVHWM`` bounds the pipes, not
        that queue. Leaving it unread is the exact thing ``_get_sockets``
        refuses to open an XPUB without a reader to avoid, except that here
        it would last for the life of the publish daemon. Presence is gone
        either way; this only stops it costing memory.
        """
        log.warning(
            "Presence is no longer being recorded on %s; draining its"
            " subscription queue so it does not grow unbounded",
            self.pub_uri,
        )
        errors = 0
        while True:
            try:
                await self.daemon_pub_sock.recv(copy=False)
            except asyncio.CancelledError:
                raise
            except zmq.error.ZMQError:
                # The socket is gone; there is nothing left to drain.
                return
            except Exception:  # pylint: disable=broad-except
                # Nothing is interpreting these any more, so there is
                # nothing to report. But a recv that keeps failing is not
                # draining anything either, and spinning on it would be
                # worse than the queue this is here to bound.
                errors += 1
                if errors >= 10:
                    log.error(
                        "Unable to drain the subscription queue on %s;" " giving up",
                        self.pub_uri,
                    )
                    return
                continue
            errors = 0

    async def _subscription_presence_loop(
        self, presence_callback, remove_presence_callback
    ):
        """The read loop proper; see ``_subscription_presence``."""
        errors = 0
        while True:
            try:
                # copy=False so the frame's 0MQ metadata survives: it is
                # where the subscriber's address comes from, the one thing a
                # subscription cannot carry itself.
                frame = await self.daemon_pub_sock.recv(copy=False)
            except asyncio.CancelledError:
                raise
            except zmq.error.ZMQError as exc:
                # The socket or its context is gone -- shutdown, or close()
                # racing the ioloop. Nothing further can be read, and looping
                # would spin this coroutine at full speed.
                # Not debug: outside shutdown this permanently ends presence
                # events and the record for this publish daemon, and that
                # should not be invisible at the default level. The socket
                # is gone with it, so there is nothing left to drain.
                log.error("Subscription reader for %s stopping: %s", self.pub_uri, exc)
                return False
            except Exception as exc:  # pylint: disable=broad-except
                errors += 1
                log.error(
                    "Exception reading subscriptions %s %s",
                    self.pub_uri,
                    exc,
                    exc_info_on_loglevel=logging.DEBUG,
                )
                if errors >= 10:
                    # Whatever this is, it is not transient. Give up rather
                    # than burn a core logging the same failure forever.
                    log.error(
                        "Too many errors reading subscriptions on %s, presence "
                        "events from this publish server will stop",
                        self.pub_uri,
                    )
                    # The socket itself is probably fine -- it is the
                    # handling that keeps failing -- so it still has to be
                    # drained.
                    return True
                continue
            errors = 0
            data = bytes(frame)
            if not data:
                continue
            verb = data[0]
            if verb not in (0, 1):
                # Not a subscription message at all. libzmq hands anything
                # else a subscriber sends straight through to the
                # application; it names nobody and is not a presence edge.
                continue
            if len(data) > _MAX_TOPIC_LEN:
                # Decoding is the expensive part and this is unauthenticated
                # input, so the length is checked before paying for it. No
                # topic this reader resolves is anywhere near this long.
                log.debug("Ignoring an implausibly long subscription topic")
                continue
            topic = data[1:].decode(errors="replace")
            # The empty topic is what every subscriber sends without
            # zmq_filtering, and broadcast / syndic are shared delivery
            # topics; none of them names anybody. Skipped explicitly so they
            # do not look like unrecognized subscribers in the log.
            if not topic or topic in ("broadcast", "syndic"):
                continue
            try:
                if verb:
                    # Shape first: an invented topic is rejected on a
                    # string test, without reaching the resolve or the
                    # stats behind it. This is unauthenticated input.
                    if not self._could_name_a_minion(topic):
                        log.debug("Ignoring an unresolvable topic %s", topic)
                        raise _Unresolved
                    minion_id = self._topic_to_minion(topic)
                    if minion_id is None:
                        # Parked rather than dropped: the key may simply not
                        # be visible yet, and libzmq will not repeat this
                        # SUBSCRIBE. Retried on the next rebuild below.
                        log.debug("Subscription from unrecognized topic %s", topic)
                        self._park_unresolved(topic, _peer_address(frame))
                        self._ensure_sweeper(presence_callback)
                        # Deliberately NOT ``continue``: the retry and the
                        # revocation prune at the foot of this loop still
                        # have to run. The rebuild that just failed to name
                        # this topic is also the one that can reveal a
                        # revoked key, and skipping it here is how a
                        # parking frame silently suppressed both.
                        raise _Unresolved
                    self._forget_unresolved(topic)
                    # setdefault, so one topic keeps one stub: the channel
                    # holds a *set* of subscribers per id, and a second stub
                    # object would survive the single unsubscribe libzmq
                    # sends when the last subscriber goes.
                    #
                    # The cost is that the address is whatever the first
                    # subscribe carried. A minion reconnecting over its own
                    # not-yet-reaped connection produces no new SUBSCRIBE --
                    # that is libzmq's refcounting, and it is what keeps the
                    # presence edges clean -- so ``show_ip`` can report the
                    # address it had before the reconnect. Under NAT that is
                    # the field most likely to have changed. Reporting the
                    # older of two live addresses is still a real address
                    # for a real connection, which the grain matching this
                    # replaces could not manage at all.
                    stub = self._present.setdefault(
                        topic, _SubscriberStub(minion_id, _peer_address(frame))
                    )
                    await presence_callback(stub, None)
                else:
                    # Deliberately not resolved through _topic_to_minion: this
                    # is keyed by topic and the stub already carries the id, so
                    # a departure is honoured even once the topic has stopped
                    # resolving. It does stop -- deleting or rejecting a key
                    # while its minion is connected takes it out of the map --
                    # and dropping the unsubscribe there would leave the minion
                    # reported present for the life of the publish daemon.
                    self._forget_unresolved(topic)
                    # It may have been retracted while still subscribed;
                    # this is the departure that finally clears it.
                    self._retracted.pop(topic, None)
                    stub = self._present.get(topic)
                    if stub is not None and remove_presence_callback is not None:
                        # Popped only once the callback has accepted it.
                        # Popping first and letting the callback raise
                        # would leave the channel holding a minion that
                        # has gone, with no redelivery possible -- libzmq
                        # sends one unsubscribe. The subscribe path above
                        # takes the same care in the other direction.
                        remove_presence_callback(stub)
                    self._present.pop(topic, None)
            except _Unresolved:
                pass
            except Exception as exc:  # pylint: disable=broad-except
                log.error(
                    "Exception handling presence for topic %s: %s",
                    topic,
                    exc,
                    exc_info_on_loglevel=logging.DEBUG,
                )
                # A callback that raised leaves this subscription unrecorded
                # in the channel, and libzmq will not deliver it again. The
                # stub is already in ``_present`` by then -- it is created
                # before the callback is awaited -- and the retry skips any
                # topic that is, so it has to come back out or the minion is
                # lost exactly as if it had never been parked.
                if verb:
                    # Unconditional, because one topic only ever has one
                    # stub: XPUB is not in verbose mode, so libzmq
                    # refcounts subscriptions per topic and delivers only
                    # the first subscribe and the last unsubscribe -- see
                    # ``_get_sockets``. A second peer subscribing to the
                    # same topic produces no frame here at all.
                    self._present.pop(topic, None)
                    self._park_unresolved(topic, _peer_address(frame))
                    self._ensure_sweeper(presence_callback)
            try:
                await self._retry_unresolved(presence_callback)
                self._prune_revoked(remove_presence_callback)
                for stub in self._readmit_restored():
                    await presence_callback(stub, None)
            except Exception as exc:  # pylint: disable=broad-except
                log.error(
                    "Exception retrying unresolved subscriptions: %s",
                    exc,
                    exc_info_on_loglevel=logging.DEBUG,
                )

    async def publish_payload(self, payload, topic_list=None, raw_payload=None):
        # ``raw_payload`` is accepted for interface parity with
        # :class:`salt.transport.tcp.PublishServer`, which uses it to
        # skip a redundant msgpack round-trip on the EP fan-out hot
        # path.  zeromq's own framing is handled by libzmq -- there is
        # no equivalent framing shortcut here, so we ignore it and
        # fall through to the normal send path with ``payload``.
        log.trace("Publish payload %r", payload)
        if self.opts["zmq_filtering"]:
            if topic_list:
                for topic in topic_list:
                    log.trace("Sending filtered data over publisher %s", self.pub_uri)
                    # zmq filters are substring match, hash the topic
                    # to avoid collisions
                    htopic = salt.utils.stringutils.to_bytes(
                        hashlib.sha1(salt.utils.stringutils.to_bytes(topic)).hexdigest()
                    )
                    await self.dpub_sock.send_multipart([htopic, payload])
                    log.trace("Filtered data has been sent")
                # Syndic broadcast
                if self.opts.get("order_masters"):
                    log.trace("Sending filtered data to syndic")
                    await self.dpub_sock.send_multipart([b"syndic", payload])
                    log.trace("Filtered data has been sent to syndic")
            # otherwise its a broadcast
            else:
                # TODO: constants file for "broadcast"
                log.trace("Sending broadcasted data over publisher %s", self.pub_uri)
                await self.dpub_sock.send_multipart([b"broadcast", payload])
                log.trace("Broadcasted data has been sent")
        else:
            log.trace("Sending ZMQ-unfiltered data over publisher %s", self.pub_uri)
            await self.dpub_sock.send(payload)
            log.trace("Unfiltered data has been sent")

    def pre_fork(self, process_manager, *args, **kwargs):
        """
        Do anything necessary pre-fork. Since this is on the master side this will
        primarily be used to create IPC channels and create our daemon process to
        do the actual publishing

        :param func process_manager: A ProcessManager, from salt.utils.process.ProcessManager
        """
        secrets = kwargs.get("secrets") or getattr(self, "secrets", None)
        process_manager.add_process(
            self.publish_daemon,
            args=(self.publish_payload,),
            kwargs={"secrets": secrets},
        )

    def connect(self, timeout=None):
        """
        Create and connect this thread's zmq socket. If a publisher socket
        already exists "pub_close" is called before creating and connecting a
        new socket.
        """
        log.debug("Connecting to pub server: %s", self.pull_uri)
        self.ctx = zmq.asyncio.Context()
        self.sock = self.ctx.socket(zmq.PUSH)
        self.sock.setsockopt(zmq.LINGER, 1)
        self.sock.connect(self.pull_uri)
        return self.sock

    def close(self):
        """
        Disconnect an existing publisher socket and remove it from the local
        thread's cache.
        """
        if self.sock is not None:
            sock = self.sock
            self.sock = None
            sock.close()
        if self.ctx and self.ctx.closed is False:
            ctx = self.ctx
            self.ctx = None
            ctx.term()
        if self._presence_task is not None:
            # Marks the reader cancelled before its socket is destroyed, so
            # the task is not left pending behind a dead socket. It does not
            # generally unwind here: ``close`` runs from ``publish_daemon``'s
            # ``finally``, after ``run_forever`` has already returned, so
            # there is no loop left to resume the coroutine and deliver the
            # CancelledError. Nothing downstream depends on it unwinding --
            # the process is going away -- but do not add cleanup to the
            # reader on the assumption that it runs.
            self._presence_task.cancel()
            self._presence_task = None
        if self.daemon_monitor:
            self.daemon_monitor.stop()
        if self.daemon_pub_sock:
            self.daemon_pub_sock.close()
        if self.daemon_pull_sock:
            self.daemon_pull_sock.close()
        if self.daemon_context:
            self.daemon_context.destroy(1)
            # self.daemon_context.term()

    async def publish(
        self, payload, **kwargs
    ):  # pylint: disable=invalid-overridden-method
        """
        Publish "load" to minions. This send the load to the publisher daemon
        process with does the actual sending to minions.

        :param dict load: A load to be sent across the wire to minions
        """
        if not self.sock:
            self.connect()
        await self.sock.send(payload)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def _finalize_zmq_context(context):
    """Bounded, wedge-safe zmq.Context teardown for ``weakref.finalize``.

    Runs when a ``RequestClient`` (or similar owner) is garbage-collected
    without an explicit ``close()`` having been called on it.  Explicitly
    destroys the ``zmq.asyncio.Context`` with a bounded linger so
    pyzmq's own ``Context.__del__`` -- which would otherwise walk the
    context's sockets and call libzmq's ``zmq_ctx_term()`` under each
    socket's native LINGER setting -- has nothing left to do.  That
    matters because pyzmq's ``__del__`` runs synchronously on whatever
    thread the last reference is dropped from, and when that thread is
    an asyncio ioloop callback ``zmq_ctx_term()`` can block the whole
    loop indefinitely.

    Register from a ``RequestClient``-alike via::

        weakref.finalize(self, _finalize_zmq_context, self.context)

    ``weakref.finalize`` fires before the type slot ``__del__`` on the
    referent runs and captures its own strong reference to ``context``,
    so this callback is guaranteed to execute exactly once and to see a
    live Context.
    """
    try:
        if context is not None and not context.closed:
            context.destroy(linger=1000)
    except Exception:  # pylint: disable=broad-except
        pass


class RequestClient(salt.transport.base.RequestClient):
    ttype = "zeromq"

    def __init__(self, opts, io_loop, linger=0):  # pylint: disable=W0231
        super().__init__(opts, io_loop)
        self.opts = opts
        # XXX Support host, port, path, instead of using get_master_uri
        self.master_uri = self.get_master_uri(opts)
        self.linger = linger
        if io_loop is None:
            self.io_loop = salt.utils.asynchronous.aioloop(
                tornado.ioloop.IOLoop.current()
            )
        else:
            self.io_loop = salt.utils.asynchronous.aioloop(io_loop)
        self.context = None
        self.send_queue = []
        # mapping of message -> future
        self.send_future_map = {}
        self._closing = False
        self.socket = None
        self._queue = asyncio.Queue()
        self._connect_lock = asyncio.Lock()
        self.send_recv_task = None
        self.send_recv_task_id = 0
        # PATCH: mirror ``AsyncReqMessageClient`` (twangboy #68637) --
        # ``_send_recv_exit_future`` is resolved by ``_send_recv`` on
        # every exit path so ``close()`` can wait for the task to drain
        # before we close the ZMQ socket + destroy the context.  Without
        # this, ``close()`` races ``_send_recv``: the task's coroutine
        # locals still hold a reference to the socket after we close it,
        # then GC runs while the io_loop is torn down, and the
        # socketpair backing the REQ socket + its internal mailbox never
        # gets released.  Observed as ~451 leaked socketpairs (~902
        # fds) per minion under sustained ``saltutil.refresh_pillar`` /
        # ``AsyncAuth`` re-auth churn, tripping the minion's 1024-file
        # ulimit "critical" threshold.
        self._send_recv_exit_future = None

    async def connect(self):  # pylint: disable=invalid-overridden-method
        async with self._connect_lock:
            if self._closing:
                # A closed ``RequestClient`` must not silently resurrect
                # itself here.  ``close_async`` cleared ``self.socket`` and
                # ``self.context`` and destroyed the underlying ZMQ Context
                # deterministically; the previous version of ``connect``
                # then unconditionally reset ``self._closing = False`` and
                # ran ``_init_socket``, which allocated a fresh Context
                # and registered a new ``weakref.finalize`` against a
                # RequestClient that no live caller was tracking any more.
                # When that RequestClient eventually got GC'd the new
                # finalizer fired from an ioloop callback and blocked in
                # ``zmq_ctx_term()``, wedging the minion.  Refuse the
                # reconnect and force the caller to construct a fresh
                # ``AsyncReqChannel`` if it needs one.  This scenario shows
                # up in practice when a coroutine captured a reference to
                # ``self.req_channel`` across an ``await`` and the
                # reconnect path (``connect_master`` / ``handle_event``
                # master-changed) swapped in a new channel before that
                # captured coroutine's next ``send`` fires.
                raise SaltClientError(
                    "RequestClient is closed; construct a new one to reconnect."
                )
            if self.socket is None:
                self._connect_called = True
                # wire up sockets
                self._init_socket()

    def _init_socket(self):
        # Clean up old task if it exists
        if self.send_recv_task is not None:
            try:
                self.send_recv_task.cancel()
            except RuntimeError:
                pass
            self.send_recv_task = None

        self.send_recv_task_id += 1

        if self.socket is not None:
            self.socket.close()
            self.socket = None

        if self.context is None:
            self.context = zmq.asyncio.Context()
            # If a caller drops this RequestClient without invoking
            # close(), pyzmq's own Context.__del__ walks the sockets
            # and calls libzmq's zmq_ctx_term() under each socket's
            # native LINGER -- from whatever thread the last reference
            # is decremented on.  When that thread is an asyncio
            # ioloop callback (RequestClient is created on such a
            # callback via _fire_master_main -> _send_req_async_main
            # -> req_channel.send -> transport.send -> connect() ->
            # _init_socket, all on the ioloop), the loop freezes.
            # ``weakref.finalize`` runs a bounded ``destroy(linger=N)``
            # first, so pyzmq's ``__del__`` sees ``closed=True`` and
            # skips the wedge-prone destroy path.
            weakref.finalize(self, _finalize_zmq_context, self.context)

        self.socket = self.context.socket(zmq.REQ)
        self.socket.setsockopt(zmq.LINGER, 1)

        # socket options
        if hasattr(zmq, "RECONNECT_IVL_MAX"):
            self.socket.setsockopt(zmq.RECONNECT_IVL_MAX, 5000)

        _set_tcp_keepalive(self.socket, self.opts)
        if self.master_uri.startswith("tcp://["):
            # Hint PF type if bracket enclosed IPv6 address
            if hasattr(zmq, "IPV6"):
                self.socket.setsockopt(zmq.IPV6, 1)
            elif hasattr(zmq, "IPV4ONLY"):
                self.socket.setsockopt(zmq.IPV4ONLY, 0)
        self.socket.linger = self.linger
        self.socket.connect(self.master_uri)
        # Fresh exit future per task -- resolved when _send_recv actually
        # returns so close() can wait for the socket to be released
        # before it's closed.
        self._send_recv_exit_future = asyncio.Future()
        self.send_recv_task = self.io_loop.create_task(
            self._send_recv(self.socket, self._queue, task_id=self.send_recv_task_id),
            name="RequestClient._send_recv",
        )
        self.send_recv_task._log_destroy_pending = False

        def _task_done(task):
            try:
                task.result()
            except (asyncio.CancelledError, zmq.eventloop.future.CancelledError):
                pass
            except Exception as exc:  # pylint: disable=broad-except
                log.error(
                    "Unhandled exception in _send_recv task: %s", exc, exc_info=True
                )

        self.send_recv_task.add_done_callback(_task_done)

    # TODO: timeout all in-flight sessions, or error
    def close(self):
        if self._closing:
            return
        self._closing = True
        # Save socket reference before clearing it for use in callback
        if hasattr(self, "_queue") and self._queue is not None:
            try:
                self._queue.put_nowait((None, None))
            except Exception:  # pylint: disable=broad-except
                pass
        # Do not cancel send_recv_task here: ``_send_recv`` must drain the
        # shutdown sentinel so TRACE logs and clean teardown match functional
        # tests (see test_request_client_send_recv_socket_closed). Reconnect
        # still cancels the task in ``_init_socket``.
        #
        # PATCH: instead of closing the socket immediately -- which races
        # ``_send_recv`` and leaves its coroutine locals holding a
        # reference to a closed socket (leaks the underlying socketpair
        # + mailbox fds) -- move socket/context tear-down into an async
        # task that first awaits ``_send_recv_exit_future``.  See
        # AsyncReqMessageClient graceful shutdown (twangboy #68637
        # chain).
        socket = self.socket
        context = self.context
        exit_future = self._send_recv_exit_future
        self.socket = None
        self.context = None
        self._send_recv_exit_future = None

        def _sync_teardown():
            if socket is not None:
                try:
                    socket.close()
                except Exception:  # pylint: disable=broad-except
                    pass
            if context is not None and not context.closed:
                try:
                    context.destroy(0)
                except Exception:  # pylint: disable=broad-except
                    pass

        async def _drain_and_close():
            if exit_future is not None:
                try:
                    await asyncio.wait_for(asyncio.shield(exit_future), timeout=5)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                except Exception:  # pylint: disable=broad-except
                    log.debug(
                        "RequestClient graceful drain failed",
                        exc_info=True,
                    )
            _sync_teardown()

        asyncio_loop = getattr(self.io_loop, "asyncio_loop", None)
        if asyncio_loop is None:
            asyncio_loop = self.io_loop
        try:
            loop_running = asyncio_loop.is_running()
        except Exception:  # pylint: disable=broad-except
            loop_running = False

        if loop_running:
            # Determine whether ``close()`` was called from the same thread
            # that is currently running the io_loop. If so, we're inside
            # async code (e.g. a coroutine finalising itself); scheduling
            # is safe and the caller will drive the loop.  Otherwise
            # (cross-thread), we block until the drain completes so the
            # caller doesn't tear down the loop while our task is pending.
            loop_thread = getattr(asyncio_loop, "_thread_id", None)
            same_thread = (
                loop_thread is not None and loop_thread == threading.get_ident()
            )
            if same_thread:
                # PATCH: same-thread + loop-running case.  We cannot block
                # (would deadlock the loop), but we also cannot rely on a
                # scheduled task actually running before the loop is torn
                # down (e.g. pytest-asyncio finishes the test coroutine
                # and closes the loop without another iteration -- the
                # ``_drain_and_close`` task is then destroyed while
                # pending and the underlying socket/context leak).
                #
                # The shutdown sentinel has already been queued above;
                # ``_send_recv`` will consume it and drop the socket
                # reference from its coroutine locals on the next loop
                # iteration (which the caller must yield to before the
                # loop is closed -- matches base-branch behavior).  Fall
                # through to sync teardown so socket/context are closed
                # deterministically before we return; do not cancel the
                # send_recv task because functional tests assert on the
                # sentinel log emitted by the graceful queue drain.
                _sync_teardown()
                return
            else:
                done_evt = threading.Event()

                async def _drain_and_signal():
                    try:
                        await _drain_and_close()
                    finally:
                        done_evt.set()

                try:
                    asyncio_loop.call_soon_threadsafe(
                        lambda: asyncio_loop.create_task(_drain_and_signal())
                    )
                    # Wait for the drain to finish so we don't return with
                    # socket/context leaked.  5s matches the drain timeout.
                    if done_evt.wait(timeout=6):
                        return
                except RuntimeError:
                    # Loop already closed; fall through to sync path.
                    pass

        # Fallback: loop is not running, or scheduling failed, or the
        # cross-thread wait timed out.  ``_send_recv`` is not going to
        # make progress in any of those cases -- close the resources
        # directly so we don't leak FDs (see #69991).
        _sync_teardown()

    async def _reconnect(self):
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        await self.connect()

    async def close_async(self):
        """Preferred close for ioloop-owning callers.

        The sync ``close()``'s same-thread + loop-running branch cannot
        await the running ``_send_recv`` task (blocking would deadlock
        the loop it is on), so it runs ``_sync_teardown`` immediately.
        ``_send_recv`` may still be holding a reference to ``socket``
        in its coroutine locals when that teardown runs, which leaves
        the ``Context`` refcount above zero.  When ``_send_recv``
        eventually exits and drops its socket reference, the
        ``Context`` is finalized -- from an ioloop callback, on the
        loop's own thread -- and pyzmq's ``Context.__del__`` can wedge
        the loop in ``zmq_ctx_term()``.

        ``close_async`` fixes the race by actually awaiting
        ``_send_recv_exit_future`` before the teardown runs.  Once
        ``_send_recv`` has drained the shutdown sentinel and returned,
        the socket / context are the only remaining references; the
        explicit ``socket.close()`` + ``context.destroy(linger=1000)``
        below then release them deterministically, with the bounded
        linger acting as a safety net so the destroy never blocks the
        caller indefinitely.

        Callers on the ioloop thread that are about to drop the
        underlying client reference (e.g. ``salt.minion`` on its
        reconnect path) should use this instead of the sync
        ``close()``.
        """
        if self._closing:
            return
        self._closing = True
        if hasattr(self, "_queue") and self._queue is not None:
            try:
                self._queue.put_nowait((None, None))
            except Exception:  # pylint: disable=broad-except
                pass
        socket = self.socket
        context = self.context
        exit_future = self._send_recv_exit_future
        self.socket = None
        self.context = None
        self._send_recv_exit_future = None
        if exit_future is not None:
            try:
                await asyncio.wait_for(asyncio.shield(exit_future), timeout=5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
            except Exception:  # pylint: disable=broad-except
                log.debug("RequestClient graceful drain failed", exc_info=True)
        if socket is not None:
            try:
                socket.close()
            except Exception:  # pylint: disable=broad-except
                pass
        if context is not None and not context.closed:
            try:
                context.destroy(linger=1000)
            except Exception:  # pylint: disable=broad-except
                pass

    async def send(self, load, timeout=60):
        """
        Return a future which will be completed when the message has a response
        """
        if not self.socket:
            await self.connect()

        future = tornado.concurrent.Future()

        message = salt.payload.dumps(load)

        self._queue.put_nowait((future, message))

        if self.opts.get("detect_mode") is True:
            timeout = 1

        if timeout is not None:
            send_timeout = self.io_loop.call_later(
                timeout, self._timeout_message, future
            )

        return await future

    def _timeout_message(self, future):
        if not future.done():
            future.set_exception(SaltReqTimeoutError("Message timed out"))

    @staticmethod
    def get_master_uri(opts):
        if "master_uri" in opts:
            return opts["master_uri"]
        if "master_ip" in opts:
            return _get_master_uri(
                opts["master_ip"],
                opts["master_port"],
                source_ip=opts.get("source_ip"),
                source_port=opts.get("source_ret_port"),
            )
        # if we've reached here something is very abnormal
        raise SaltException("ReqChannel: missing master_uri/master_ip in self.opts")

    async def _send_recv(
        self, socket, queue, task_id=None, _TimeoutError=tornado.gen.TimeoutError
    ):
        """
        Long running send/receive coroutine. This should be started once for
        each socket created. Once started, the coroutine will run until the
        socket is closed. A future and message are pulled from the queue. The
        message is sent and the reply socket is polled for a response while
        checking the future to see if it was timed out.
        """
        # PATCH: capture the exit future for THIS task instance up front.
        # ``self._send_recv_exit_future`` may be swapped out by
        # ``_init_socket`` on reconnect while we're still running, so
        # remember the one that belongs to us and resolve it in
        # ``finally`` -- ``close()`` waits on this to know the socket is
        # safe to close without racing our coroutine locals.  See
        # AsyncReqMessageClient graceful shutdown (twangboy #68637).
        exit_future = self._send_recv_exit_future
        try:
            asyncio.current_task()._log_destroy_pending = False
        except (RuntimeError, AttributeError):
            pass
        try:
            send_recv_running = True
            # Hold on to the socket so we'll still have a reference to it after the
            # close method is called. This allows us to fail gracefully once it's
            # been closed.
            while send_recv_running:
                if task_id is not None and task_id != self.send_recv_task_id:
                    break

                try:
                    # Use a small timeout to allow periodic task_id checks
                    future, message = await asyncio.wait_for(queue.get(), 0.3)
                except asyncio.TimeoutError:
                    continue
                except (asyncio.CancelledError, asyncio.exceptions.CancelledError):
                    break

                if task_id is not None and task_id != self.send_recv_task_id:
                    # Re-queue the message so the new task can pick it up
                    self._queue.put_nowait((future, message))
                    log.trace(
                        "Task %s is no longer active after queue.get. Re-queued and exiting.",
                        task_id,
                    )
                    break

                if future is None:
                    log.trace("Received send/recv shutdown sentinal")
                    send_recv_running = False
                    break

                try:
                    # Wait for socket to be ready for sending
                    if not await socket.poll(300, zmq.POLLOUT):
                        if not future.done():
                            future.set_exception(
                                SaltReqTimeoutError("Socket not ready for sending")
                            )
                        if not self._closing:
                            await self._reconnect()
                        break

                    await socket.send(message)
                except (
                    zmq.eventloop.future.CancelledError,
                    asyncio.CancelledError,
                ) as exc:
                    send_recv_running = False
                    if not future.done():
                        future.set_exception(exc)
                    break
                except zmq.ZMQError as exc:
                    if exc.errno == zmq.EAGAIN:
                        # Re-queue and try again
                        self._queue.put_nowait((future, message))
                        continue
                    if not future.done():
                        future.set_exception(exc)
                    # Add a small delay before reconnecting to prevent storms
                    await asyncio.sleep(0.1)
                    if not self._closing:
                        await self._reconnect()
                    break

                received = False
                ready = False
                while True:
                    try:
                        # Time is in milliseconds.
                        ready = await socket.poll(300, zmq.POLLIN)
                    except (
                        asyncio.CancelledError,
                        zmq.eventloop.future.CancelledError,
                        asyncio.exceptions.CancelledError,
                    ) as exc:
                        send_recv_running = False
                        if not future.done():
                            future.set_exception(exc)
                        break
                    except zmq.ZMQError as exc:
                        send_recv_running = False
                        if not future.done():
                            future.set_exception(exc)
                        if not self._closing:
                            await self._reconnect()
                        break

                    if ready:
                        try:
                            recv = await socket.recv()
                            received = True
                        except (
                            asyncio.CancelledError,
                            zmq.eventloop.future.CancelledError,
                            asyncio.exceptions.CancelledError,
                        ) as exc:
                            send_recv_running = False
                            if not future.done():
                                future.set_exception(exc)
                        except zmq.ZMQError as exc:
                            send_recv_running = False
                            if not future.done():
                                future.set_exception(exc)
                            if not self._closing:
                                await self._reconnect()
                            break
                        break
                    elif future.done():
                        break

                if future.done():
                    if future.cancelled():
                        send_recv_running = False
                        break
                    exc = future.exception()
                    if exc is None:
                        continue
                    if isinstance(
                        exc,
                        (asyncio.CancelledError, zmq.eventloop.future.CancelledError),
                    ):
                        send_recv_running = False
                        break
                    if isinstance(exc, SaltReqTimeoutError):
                        log.error(
                            "Request timed out while waiting for a response. reconnecting."
                        )
                    elif isinstance(exc, zmq.ZMQError) and exc.errno == zmq.EAGAIN:
                        # Resource temporarily unavailable is normal during reconnections
                        log.trace("Socket EAGAIN during send/recv loop. reconnecting.")
                    else:
                        log.error(
                            "The request ended with an error. reconnecting. %r", exc
                        )
                    if not self._closing:
                        await self._reconnect()
                    send_recv_running = False
                elif received:
                    try:
                        data = salt.payload.loads(recv)
                        if not future.done():
                            future.set_result(data)
                    except Exception as exc:  # pylint: disable=broad-except
                        log.error("Failed to deserialize response: %s", exc)
                        if not future.done():
                            future.set_exception(exc)
            log.trace("Send and receive coroutine ending %s", socket)
        finally:
            # PATCH: signal ``close()`` that the coroutine has exited
            # and the socket/context are safe to tear down.
            if exit_future is not None and not exit_future.done():
                exit_future.set_result(None)
