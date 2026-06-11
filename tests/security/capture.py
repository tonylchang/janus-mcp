"""In-memory client<->server session that records every JSON-RPC frame.

Mirrors mcp.shared.memory.create_connected_server_and_client_session, but pumps
messages through recording forwarders so the test can grep the exact bytes that
would have crossed a stdio transport. SessionMessages are serialized with the
same pydantic settings the wire codec uses (by_alias, exclude_none).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import anyio
from mcp.client.session import ClientSession, ElicitationFnT
from mcp.server.fastmcp import FastMCP
from mcp.shared.message import SessionMessage


def frame_to_json(item: SessionMessage | Exception) -> str:
    if isinstance(item, Exception):
        return f'{{"_capture_exception": "{type(item).__name__}"}}'
    return item.message.model_dump_json(by_alias=True, exclude_none=True)


@asynccontextmanager
async def capture_session(
    server: FastMCP,
    frames: list[str],
    elicitation_callback: ElicitationFnT | None = None,
):
    """Yields a connected ClientSession; every frame in both directions is
    appended to ``frames`` as serialized JSON."""

    async def pump(
        source: Any,  # MemoryObjectReceiveStream
        sink: Any,  # MemoryObjectSendStream
    ) -> None:
        async with source, sink:
            async for item in source:
                frames.append(frame_to_json(item))
                await sink.send(item)

    # client -> [pump] -> server, and server -> [pump] -> client
    client_out_send, client_out_recv = anyio.create_memory_object_stream[
        SessionMessage | Exception
    ](8)
    to_server_send, to_server_recv = anyio.create_memory_object_stream[SessionMessage | Exception](
        8
    )
    server_out_send, server_out_recv = anyio.create_memory_object_stream[
        SessionMessage | Exception
    ](8)
    to_client_send, to_client_recv = anyio.create_memory_object_stream[SessionMessage | Exception](
        8
    )

    mcp_server = server._mcp_server

    async with anyio.create_task_group() as tg:
        tg.start_soon(pump, client_out_recv, to_server_send)
        tg.start_soon(pump, server_out_recv, to_client_send)
        tg.start_soon(
            lambda: mcp_server.run(
                to_server_recv,
                server_out_send,
                mcp_server.create_initialization_options(),
                raise_exceptions=False,
            )
        )
        try:
            async with ClientSession(
                read_stream=to_client_recv,
                write_stream=client_out_send,
                elicitation_callback=elicitation_callback,
            ) as client:
                await client.initialize()
                yield client
        finally:
            tg.cancel_scope.cancel()
