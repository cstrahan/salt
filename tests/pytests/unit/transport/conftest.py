"""
Fixtures for unit transport tests.
"""

# pylint: disable=unused-import

import pathlib
import shutil
import tempfile

import pytest  # noqa: F401

# Import SSL certificate fixtures
from tests.support.pytest.transport_ssl import (
    ssl_ca_cert_key,
    ssl_client_cert_key,
    ssl_master_config,
    ssl_minion_a_cert_key,
    ssl_minion_a_config,
    ssl_minion_b_cert_key,
    ssl_minion_b_config,
    ssl_minion_cert_key_with_id,
    ssl_minion_config,
    ssl_server_cert_key,
)


@pytest.fixture
def ipc_dir():
    """
    A directory short enough to hold a unix socket path.

    ``sockaddr_un.sun_path`` is 104 bytes on macOS (108 on Linux), and
    pytest's ``tmp_path`` -- which encodes the repository path and the
    test name -- routinely exceeds that on its own, so tests that bind an
    IPC socket cannot use it.
    """
    path = pathlib.Path(tempfile.mkdtemp(prefix="salt-ipc-"))
    try:
        yield path
    finally:
        shutil.rmtree(str(path), ignore_errors=True)
