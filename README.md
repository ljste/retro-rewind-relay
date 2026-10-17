# Retro Rewind browser socket relay

This service forwards the browser port's TCP and UDP socket operations over a
WebSocket connection. Game execution, rendering, audio, and saves stay on the
player's device. The relay contains no game assets or player saves.

Deploy `render.yaml` using Render's Free web service plan, or build
`Dockerfile.relay`. Set `ALLOWED_ORIGINS` to the website origins, separated by
commas. `PORT` defaults to `10000`.

The website connects to `/network` with subprotocol `wiicompiled-net-v1`.
`/health` returns HTTP 200 for readiness and startup warmup. Hosted sessions
reject private and local destinations. Free hosting can sleep when idle and
has usage limits; the website wakes the relay before launching the engine.

Source is also maintained in the WiiCompiled browser workspace under `web/`.
Licensed under GPL-3.0. Python dependencies are listed in `requirements.txt`.

Direct UDP through Render changes its public port by destination and fails
Retro WFC peer negotiation (error 86420). For a stable public UDP endpoint, set
`TURN_HOST`, `TURN_PORT` (default `443`), `TURN_USERNAME`, and `TURN_PASSWORD`.
The connection to TURN uses TLS by default. Credentials remain on this server.
Cloudflare deployments can instead set `CLOUDFLARE_TURN_KEY_ID` and
`CLOUDFLARE_TURN_API_TOKEN`. Each browser connection receives fresh 24-hour
credentials from Cloudflare's HTTPS API. If issuance fails, the relay closes
that connection rather than falling back to direct UDP.
The TURN backend has passed local coturn integration checks; hosted credentials
and a real online race are still needed to establish deployment readiness.
