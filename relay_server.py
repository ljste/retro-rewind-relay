"""Run the socket relay as a standalone hosted WebSocket service."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from http import HTTPStatus
from urllib.request import Request as HttpRequest, urlopen

from websockets.asyncio.server import ServerConnection, serve
from websockets.http11 import Request, Response

from network_relay import HEADER, PROTOCOL, RelaySession, TurnConfig


def turn_config() -> TurnConfig | None:
    key_id = os.environ.get("CLOUDFLARE_TURN_KEY_ID")
    if key_id:
        request = HttpRequest(
            f"https://rtc.live.cloudflare.com/v1/turn/keys/{key_id}/credentials/generate-ice-servers",
            data=json.dumps({"ttl": 86400}).encode(),
            headers={"Authorization": f"Bearer {os.environ['CLOUDFLARE_TURN_API_TOKEN']}",
                     "Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=15) as response:
            payload = json.loads(response.read(1024 * 1024))
        servers = payload.get("iceServers") if isinstance(payload, dict) else None
        if isinstance(servers, list):
            for server in servers:
                if not isinstance(server, dict):
                    continue
                username, password = server.get("username"), server.get("credential")
                if isinstance(username, str) and username and isinstance(password, str) and password:
                    return TurnConfig("turn.cloudflare.com", 443, username, password)
        raise ValueError("Cloudflare did not return TURN credentials")

    host = os.environ.get("TURN_HOST")
    return (TurnConfig(host, int(os.environ.get("TURN_PORT", "443")),
                       os.environ["TURN_USERNAME"], os.environ["TURN_PASSWORD"],
                       tls=os.environ.get("TURN_TLS", "1") != "0") if host else None)


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
    try:
        turn = await asyncio.to_thread(turn_config)
    except Exception:
        logging.error("Unable to obtain TURN credentials")
        await connection.close(1011, "TURN credential service unavailable")
        return
    await RelaySession(connection, public_only=True, turn=turn).run()


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
