#!/usr/bin/env node
/**
 * End-to-end check of the plugin's optional OAuth gate.
 *
 *   node scripts/verify-oauth.mjs --password <generated password> [--base http://127.0.0.1:23120]
 *
 * Reads the public origin from the plugin's discovery metadata, so it works
 * with any configured origin and any MCP port. Never prints the password.
 * Exits non-zero on the first failed expectation.
 */
import { createHash, randomBytes } from "node:crypto";

const args = process.argv.slice(2);
const getArg = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : fallback;
};

const base = (getArg("base", "http://127.0.0.1:23120") || "").replace(/\/$/, "");
const password = getArg("password", process.env.OAUTH_PASSWORD || "");
if (!password) {
  console.error("Missing --password (Zotero → MCP preferences → Generate / rotate authorization password)");
  process.exit(2);
}

const REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";
let checks = 0;

function pass(label) {
  checks += 1;
  console.log(`PASS  ${label}`);
}

function fail(label, detail) {
  console.error(`FAIL  ${label}`);
  if (detail !== undefined) console.error("      " + (typeof detail === "string" ? detail : JSON.stringify(detail)));
  process.exit(1);
}

async function req(path, { method = "GET", headers = {}, body } = {}) {
  const res = await fetch(base + path, { method, headers, body, redirect: "manual" });
  const text = await res.text();
  return { status: res.status, headers: res.headers, text };
}

function json(res) {
  try { return JSON.parse(res.text); } catch { return null; }
}

// 0. server is up
const ping = await req("/ping");
ping.status === 200 ? pass("server reachable (/ping 200)") : fail("server reachable", ping.status);

// 1. protected resource metadata
const prm = await req("/.well-known/oauth-protected-resource");
const prmBody = json(prm);
prm.status === 200 && prmBody?.resource?.endsWith("/mcp")
  ? pass(`protected-resource metadata (resource=${prmBody.resource})`)
  : fail("protected-resource metadata", prm.text);
const origin = prmBody.authorization_servers?.[0];
origin ? pass(`authorization server advertised (${origin})`) : fail("authorization server advertised", prmBody);

// 2. authorization-server metadata
const asm = await req("/.well-known/oauth-authorization-server");
const asmBody = json(asm);
asm.status === 200 && asmBody?.authorization_endpoint === `${origin}/oauth/authorize`
  ? pass("authorization-server metadata endpoints")
  : fail("authorization-server metadata", asm.text);
asmBody.code_challenge_methods_supported?.includes("S256")
  ? pass("PKCE S256 advertised")
  : fail("PKCE S256 advertised", asmBody);

// 3. unauthenticated MCP call must be refused with a challenge
const anon = await req("/mcp", {
  method: "POST",
  headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
});
anon.status === 401 && /Bearer/.test(anon.headers.get("www-authenticate") || "")
  ? pass("unauthenticated /mcp refused with WWW-Authenticate")
  : fail("unauthenticated /mcp refused", `${anon.status} ${anon.headers.get("www-authenticate")}`);

const bogus = await req("/mcp", {
  method: "POST",
  headers: { Authorization: "Bearer deadbeef", "Content-Type": "application/json" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
});
bogus.status === 401 ? pass("forged bearer token refused") : fail("forged bearer token refused", bogus.status);

// 4. registration rejects unsafe redirects, accepts the connector callback
const badRedirect = await req("/oauth/register", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ redirect_uris: ["http://evil.example/cb"] }),
});
badRedirect.status === 400 ? pass("plain-HTTP non-loopback redirect rejected") : fail("unsafe redirect rejected", badRedirect.status);

const reg = await req("/oauth/register", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }),
});
const regBody = json(reg);
reg.status === 201 && regBody?.client_id
  ? pass(`dynamic client registration (client_id ${String(regBody.client_id).slice(0, 12)}…)`)
  : fail("dynamic client registration", reg.text);

// 5. authorize page renders for a registered client
const verifier = randomBytes(32).toString("hex");
const challenge = createHash("sha256").update(verifier).digest("base64url");
const authFields = new URLSearchParams({
  response_type: "code",
  client_id: regBody.client_id,
  redirect_uri: REDIRECT,
  code_challenge: challenge,
  code_challenge_method: "S256",
  resource: `${origin}/mcp`,
  state: "verify-state",
});
const page = await req(`/oauth/authorize?${authFields}`);
page.status === 200 && /name="password"/.test(page.text)
  ? pass("authorization page served")
  : fail("authorization page served", page.status);

// 6. wrong password is refused
const wrong = new URLSearchParams(authFields);
wrong.set("password", "definitely-not-the-password");
const denied = await req("/oauth/authorize", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: wrong.toString(),
});
denied.status === 401 ? pass("wrong password refused (401)") : fail("wrong password refused", denied.status);

// 7. correct password issues a code
const good = new URLSearchParams(authFields);
good.set("password", password);
const accepted = await req("/oauth/authorize", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: good.toString(),
});
if (accepted.status !== 302) fail("password accepted (expect 302 redirect)", `${accepted.status} ${accepted.text.slice(0, 200)}`);
const location = new URL(accepted.headers.get("location") || "");
const code = location.searchParams.get("code");
location.origin === "https://chatgpt.com" && code
  ? pass("password accepted, code redirected to the client callback")
  : fail("redirect to client callback", location.href);
location.searchParams.get("state") === "verify-state" ? pass("state round-trip preserved") : fail("state round-trip", location.search);

// 8. code exchange, then an authenticated MCP call
const exchange = new URLSearchParams({
  grant_type: "authorization_code",
  code,
  client_id: regBody.client_id,
  redirect_uri: REDIRECT,
  code_verifier: verifier,
  resource: `${origin}/mcp`,
});
const token = await req("/oauth/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: exchange.toString(),
});
const tokenBody = json(token);
token.status === 200 && tokenBody?.access_token
  ? pass("authorization code exchanged for an access token")
  : fail("token exchange", `${token.status} ${token.text}`);

const authed = await req("/mcp", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${tokenBody.access_token}`,
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  },
  body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
});
authed.status !== 401
  ? pass(`authenticated /mcp accepted (status ${authed.status}, no 401)`)
  : fail("authenticated /mcp accepted", authed.status);

// 9. the code is single use
const replay = await req("/oauth/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: exchange.toString(),
});
replay.status === 400 ? pass("authorization code replay rejected") : fail("code replay rejected", replay.status);

console.log(`\nOK — ${checks} checks passed against ${base} (origin ${origin}).`);
