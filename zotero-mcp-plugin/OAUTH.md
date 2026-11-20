# Optional OAuth for remote MCP clients

The plugin can serve remote MCP clients (for example the ChatGPT web workspace)
over HTTPS with an **optional, self-hosted** OAuth 2.0 authorization-code flow
using PKCE. No reverse proxy and no third-party authorization server are needed:
a Cloudflare Tunnel (or any HTTPS tunnel) fronts the loopback listener and
provides the `https://` origin. OAuth is **off by default**; clients that never
enable it get exactly the current local behaviour.

## Listener layout — authentication per entry point

Authentication follows the **socket that accepted the request**. Host, peer IP,
`Origin` and `X-Forwarded-*` headers are never consulted.

| Allow remote access | OAuth | MCP port (default `23120`) | Authenticated listener (MCP port + 1, default `23121`) |
| :-- | :-- | :-- | :-- |
| off | off | loopback only, no auth | closed |
| off | on | loopback only, no auth | closed |
| on | off | all interfaces, no auth | closed |
| on | on | all interfaces, no auth | loopback only, Bearer token required |

> **This is deliberately different from the original proposal, which forced the
> MCP port back to loopback whenever OAuth was enabled.** Here OAuth is a
> per-entry-point policy: the local MCP port stays unauthenticated and the
> authenticated endpoint is a separate listener on `MCP port + 1`. The tunnel
> must therefore point at **`MCP port + 1`**. A tunnel pointed at the plain MCP
> port keeps reaching an unauthenticated endpoint — the plugin does not block
> that, and that is the trade-off of this entry-point design.

## Configure Zotero

1. Start **Enable server** and choose an **MCP server port** (default `23120`).
   With OAuth enabled the port must stay at or below `65534`, so that `port + 1`
   remains a valid TCP port.
2. Enable **Allow remote access**. This binds the MCP port to all interfaces.
3. Configure your Cloudflare Tunnel to forward
   `https://zotero.example.com` to `http://127.0.0.1:<MCP port + 1>` on the same
   machine — the **authenticated** listener. Do **not** point the tunnel at
   `<MCP port>` (the unauthenticated one). Replace the example hostname with your
   own.
4. In Zotero MCP preferences, enter `https://zotero.example.com` as the
   **Public HTTPS origin** (without `/mcp`).
5. Click **Generate / rotate authorization password**. The password is stored in
   Zotero's local login manager, so **Show password** and **Copy password** keep
   working after a restart; plugin preferences only store a salted SHA-256
   digest. Rotating the password invalidates existing authorizations and client
   registrations.
6. Enable **OAuth authorization**.
7. In an AI client that supports custom remote MCP servers, connect the
   Streamable HTTP URL `https://zotero.example.com/mcp`, choose OAuth, and enter
   the generated password on the authorization page.

Do not expose either local port through router port forwarding. The public
endpoint must be HTTPS.

## Endpoints

- `GET /.well-known/oauth-protected-resource`
- `GET /.well-known/oauth-authorization-server`
- `POST /oauth/register` — dynamic client registration (unauthenticated, as required for first contact)
- `GET /oauth/authorize`, `POST /oauth/authorize` — password login, S256 PKCE only
- `POST /oauth/token` — `authorization_code` and `refresh_token` grants

Access tokens are opaque Bearer tokens with a 24-hour TTL. Refresh tokens are
issued when the client requested the `refresh_token` grant and rotate on every
use. Authorization codes are single-use and expire after 5 minutes.

## State and limits

- Client registrations are held in memory up to 128 at a time. When the limit is
  reached, the oldest registration **without a live token** is evicted instead
  of refusing new registrations. Registration metadata is capped at 3 redirect
  URIs of at most 512 characters each, and requests at most 8 KiB.
- Only **registrations that hold a live token** are written to preferences (at
  most 32), together with at most 64 access and 64 refresh tokens. A burst of
  unauthenticated registrations therefore cannot lock out real connectors or grow
  the preference past the string-pref limits. Tokens are stored as SHA-256
  digests, never as plaintext.
- Unused registrations, pending codes and expired tokens are process-local and
  are dropped on restart.
- OAuth is disabled by default. If OAuth is enabled but incompletely configured,
  the OAuth endpoints return `503` and `/mcp` fails closed with `401` and a
  `WWW-Authenticate: Bearer` challenge. `/ping` stays a public health check.
- Changing the public origin or the authorization password revokes every
  existing session and client registration.

## Smoke checks

```bash
BASE=https://zotero.example.com
curl -i "$BASE/.well-known/oauth-protected-resource"
curl -i "$BASE/.well-known/oauth-authorization-server"
curl -i -X POST "$BASE/mcp" -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# Without a valid OAuth access token the last call MUST return HTTP 401.
```

Never publish the authorization password, an access token or a refresh token in
Git, screenshots, logs or public discussions.
