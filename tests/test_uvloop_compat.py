"""Regression test: pyrad2's async client must work under uvloop.

uvloop's ``UDPTransport`` satisfies the ``asyncio.DatagramTransport``
protocol structurally but does not subclass it. A previous nominal
``isinstance`` check in ``DatagramProtocolClient.connection_made`` broke
under uvloop (i.e. inside any FastAPI / Uvicorn host running on uvloop).
This test pins the duck-typed behaviour.
"""

import asyncio
import sys
from unittest.mock import MagicMock

import pytest

uvloop = pytest.importorskip("uvloop")

if sys.platform == "win32":
    pytest.skip("uvloop does not support Windows", allow_module_level=True)


def test_connection_made_accepts_uvloop_transport():
    from pyrad2.client_async import DatagramProtocolClient

    async def scenario():
        proto = DatagramProtocolClient(
            server="127.0.0.1",
            port=0,
            client=MagicMock(),
            retries=1,
            timeout=0.1,
        )
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: proto, local_addr=("127.0.0.1", 0)
        )
        try:
            # The duck-typed check accepted uvloop's transport rather
            # than failing the old ``isinstance(..., asyncio.DatagramTransport)``
            # assertion. Confirm the transport really is uvloop's and not
            # asyncio's, so a regression to the nominal check would be caught.
            assert proto.transport is not None
            assert hasattr(proto.transport, "sendto")
            assert type(proto.transport).__module__.startswith("uvloop")
        finally:
            if proto.timeout_future is not None:
                proto.timeout_future.cancel()
                try:
                    await proto.timeout_future
                except asyncio.CancelledError:
                    pass
            transport.close()

    with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
        runner.run(scenario())
