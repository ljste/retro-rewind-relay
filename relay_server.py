"""Run the socket relay as a standalone hosted WebSocket service."""
from __future__ import annotations

import asyncio
import logging
import os
from http import HTTPStatus

from websockets.asyncio.server import ServerConnection, serve
from websockets.http11 import Request, Response

from network_relay import HEADER, PROTOCOL, RelaySession


def health(connection: ServerConnection, request: Request) -> Response | None:
    if request.path != "/health":
        return None
    response = connection.respond(HTTPStatus.OK, "ok\n")
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Cache-Control"] = "no-store"
    return response


async def accept(connection: ServerConnection) -> None:
    if connection.request is None or connection.request.path != "/network":
        await connection.close(1008, "Unknown relay route")
        return
    await RelaySession(connection, public_only=True).run()


async def main() -> None:
    origins = [origin.strip() for origin in os.environ["ALLOWED_ORIGINS"].split(",") if origin.strip()]
    if not origins:
        raise ValueError("ALLOWED_ORIGINS must contain the website origin")
    async with serve(accept, "0.0.0.0", int(os.environ.get("PORT", "10000")),
                     origins=origins, subprotocols=[PROTOCOL], process_request=health,
                     compression=None, max_size=1024 * 1024 + HEADER.size) as server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
