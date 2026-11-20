import { MCPAuthServer, normalizeOAuthOrigin, arrivesThroughProxy } from "../src/modules/oauthServer.ts";
import { expect } from "chai";

const BASE = "https://zotero.example.com";
const CALLBACK = "https://chatgpt.com/connector_platform_oauth_redirect";
const PREFIX = "extensions.zotero.zotero-mcp-plugin.oauth.";
const HEADERS_JSON = "Content-Type: application/json\r\n";
const HEADERS_FORM = "Content-Type: application/x-www-form-urlencoded\r\n";

async function challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("Zotero MCP OAuth (opt-in)", function () {
  let server: MCPAuthServer;
  const store = new Map<string, unknown>();
  let vaultPassword: string | null = null;

  beforeEach(function () {
    store.clear();
    vaultPassword = null;
    server = new MCPAuthServer({
      get: (key) => store.get(key),
      set: (key, value) => { store.set(key, value); },
    }, {
      read: () => vaultPassword,
      write: (value) => { vaultPassword = value; },
    });
  });

  it("requires a valid, pinned HTTPS origin", function () {
    expect(normalizeOAuthOrigin(BASE)).to.equal(BASE);
    expect(normalizeOAuthOrigin("http://zotero.example.com")).to.equal(null);
    expect(normalizeOAuthOrigin(`${BASE}/mcp`)).to.equal(null);
    expect(normalizeOAuthOrigin("https://user:pass@zotero.example.com")).to.equal(null);
  });

  it("is disabled by default and never accepts an unauthenticated token", async function () {
    expect(server.isEnabled()).to.equal(false);
    expect(await server.isAuthorized("Authorization: Bearer invalid\r\n")).to.equal(false);
    const metadata = await server.handleRequest("GET", "/.well-known/oauth-protected-resource", new URLSearchParams(), "", "");
    expect(metadata?.status).to.equal(404);
  });

  it("registers a client, checks PKCE, rejects replay, and revokes on rotation", async function () {
    store.set(`${PREFIX}serverUrl`, BASE);
    const password = await server.generatePassword();
    expect(store.get(`${PREFIX}passwordHash`)).not.to.equal(password);
    expect(await server.getStoredPassword()).to.equal(password);
    const reloaded = new MCPAuthServer({
      get: (key) => store.get(key),
      set: (key, value) => { store.set(key, value); },
    }, { read: () => vaultPassword, write: (value) => { vaultPassword = value; } });
    expect(await reloaded.getStoredPassword()).to.equal(password);
    store.set(`${PREFIX}enabled`, true);

    const meta = await server.handleRequest("GET", "/.well-known/oauth-protected-resource", new URLSearchParams(), "", "");
    expect(meta?.status).to.equal(200);
    expect(JSON.parse(meta!.body).resource).to.equal(`${BASE}/mcp`);

    const invalid = await server.handleRequest("POST", "/oauth/register", new URLSearchParams(),
      JSON.stringify({ redirect_uris: ["http://evil.example/callback"] }), HEADERS_JSON);
    expect(invalid?.status).to.equal(400);

    const registered = await server.handleRequest("POST", "/oauth/register", new URLSearchParams(),
      JSON.stringify({ redirect_uris: [CALLBACK], token_endpoint_auth_method: "none" }), HEADERS_JSON);
    expect(registered?.status).to.equal(201);
    const id = JSON.parse(registered!.body).client_id;

    const verifier = "a".repeat(64);
    const fields = new URLSearchParams({
      response_type: "code", client_id: id, redirect_uri: CALLBACK,
      code_challenge_method: "S256", code_challenge: await challenge(verifier),
      resource: `${BASE}/mcp`, state: "state-value",
    });
    const authorize = await server.handleRequest("GET", "/oauth/authorize", fields, "", "");
    expect(authorize?.status).to.equal(200);
    const login = new URLSearchParams(fields);
    login.set("password", "incorrect");
    const denied = await server.handleRequest("POST", "/oauth/authorize", new URLSearchParams(), login.toString(), HEADERS_FORM);
    expect(denied?.status).to.equal(401);

    login.set("password", password);
    const accepted = await server.handleRequest("POST", "/oauth/authorize", new URLSearchParams(), login.toString(), HEADERS_FORM);
    expect(accepted?.status).to.equal(302);
    const location = new URL(accepted!.headers.Location);
    expect(location.origin).to.equal("https://chatgpt.com");
    expect(location.searchParams.get("state")).to.equal("state-value");

    const exchange = new URLSearchParams({
      grant_type: "authorization_code", code: location.searchParams.get("code")!,
      client_id: id, redirect_uri: CALLBACK, code_verifier: verifier,
      resource: `${BASE}/mcp`,
    });
    const token = await server.handleRequest("POST", "/oauth/token", new URLSearchParams(), exchange.toString(), HEADERS_FORM);
    expect(token?.status).to.equal(200);
    const issued = JSON.parse(token!.body);
    const access = issued.access_token;
    expect(await server.isAuthorized(`Authorization: Bearer ${access}`)).to.equal(true);
    const rawState = String(store.get(`${PREFIX}persistentState`));
    expect(rawState).not.to.contain(access);
    expect(rawState).not.to.contain(issued.refresh_token);
    const persistedState = JSON.parse(String(store.get(`${PREFIX}persistentState`)));
    // Only the registration that holds a live token is durable.
    expect(persistedState.clients.length).to.equal(1);
    expect(persistedState.tokens.length).to.equal(1);
    expect(persistedState.refreshTokens.length).to.equal(1);
    const prefs = { get: (key: string) => store.get(key), set: (key: string, value: unknown) => { store.set(key, value); } };
    const restarted = new MCPAuthServer(prefs);
    expect(await restarted.isAuthorized(`Authorization: Bearer ${access}`)).to.equal(true);
    const refreshFields = new URLSearchParams({
      grant_type: "refresh_token", client_id: id,
      refresh_token: issued.refresh_token, resource: `${BASE}/mcp`,
    });
    const renewedResponse = await restarted.handleRequest("POST", "/oauth/token", new URLSearchParams(), refreshFields.toString(), HEADERS_FORM);
    expect(renewedResponse?.status).to.equal(200);
    const renewed = JSON.parse(renewedResponse!.body);
    expect(renewed.refresh_token).not.to.equal(issued.refresh_token);
    expect(await new MCPAuthServer(prefs).isAuthorized(`Authorization: Bearer ${renewed.access_token}`)).to.equal(true);
    const replayRefresh = await restarted.handleRequest("POST", "/oauth/token", new URLSearchParams(), refreshFields.toString(), HEADERS_FORM);
    expect(replayRefresh?.status).to.equal(400);
    const replay = await server.handleRequest("POST", "/oauth/token", new URLSearchParams(), exchange.toString(), HEADERS_FORM);
    expect(replay?.status).to.equal(400);

    await server.generatePassword();
    expect(await server.isAuthorized(`Authorization: Bearer ${access}`)).to.equal(false);
  });

  it("bounds registration metadata and never persists unauthenticated clients", async function () {
    store.set(`${PREFIX}serverUrl`, BASE);
    await server.generatePassword();
    store.set(`${PREFIX}enabled`, true);

    const tooMany = await server.handleRequest("POST", "/oauth/register", new URLSearchParams(),
      JSON.stringify({ redirect_uris: [1, 2, 3, 4].map((n) => `https://chatgpt.com/cb-${n}`) }), HEADERS_JSON);
    expect(tooMany?.status).to.equal(400);
    const tooLong = await server.handleRequest("POST", "/oauth/register", new URLSearchParams(),
      JSON.stringify({ redirect_uris: [`https://chatgpt.com/${"a".repeat(512)}`] }), HEADERS_JSON);
    expect(tooLong?.status).to.equal(400);

    for (let i = 0; i < 128; i++) {
      const registered = await server.handleRequest("POST", "/oauth/register", new URLSearchParams(),
        JSON.stringify({ redirect_uris: [CALLBACK] }), HEADERS_JSON);
      expect(registered?.status).to.equal(201);
    }
    // The cap evicts the oldest registration that holds no token instead of
    // refusing every new connector forever.
    const afterCap = await server.handleRequest("POST", "/oauth/register", new URLSearchParams(),
      JSON.stringify({ redirect_uris: [CALLBACK] }), HEADERS_JSON);
    expect(afterCap?.status).to.equal(201);

    const persisted = JSON.parse(String(store.get(`${PREFIX}persistentState`)));
    expect(persisted.clients).to.deep.equal([]);
    expect(persisted.tokens).to.deep.equal([]);
  });

  it("writes the password through the Zotero 8 async Login Manager", async function () {
    const calls: string[] = [];
    const info: any = { init: (...args: any[]) => { info.password = args[4]; } };
    const manager = {
      findLogins: () => [],
      addLoginAsync: async () => { calls.push("addLoginAsync"); },
      addLogin: () => { calls.push("addLogin"); },
    };
    const scope = globalThis as any;
    const previous = { Cc: scope.Cc, Ci: scope.Ci };
    scope.Cc = {
      "@mozilla.org/login-manager;1": { getService: () => manager },
      "@mozilla.org/login-manager/loginInfo;1": { createInstance: () => info },
    };
    scope.Ci = { nsILoginManager: {}, nsILoginInfo: {} };
    try {
      const local = new MCPAuthServer({
        get: (key: string) => store.get(key),
        set: (key: string, value: unknown) => { store.set(key, value); },
      });
      const password = await local.generatePassword();
      expect(calls).to.deep.equal(["addLoginAsync"]);
      expect(info.password).to.equal(password);
    } finally {
      if (previous.Cc === undefined) delete scope.Cc; else scope.Cc = previous.Cc;
      if (previous.Ci === undefined) delete scope.Ci; else scope.Ci = previous.Ci;
    }
  });

  it("falls back to the synchronous Login Manager on Zotero 7", async function () {
    const calls: string[] = [];
    const manager = {
      findLogins: () => [],
      addLogin: () => { calls.push("addLogin"); },
    };
    const scope = globalThis as any;
    const previous = { Cc: scope.Cc, Ci: scope.Ci };
    scope.Cc = {
      "@mozilla.org/login-manager;1": { getService: () => manager },
      "@mozilla.org/login-manager/loginInfo;1": { createInstance: () => ({ init: () => undefined }) },
    };
    scope.Ci = { nsILoginManager: {}, nsILoginInfo: {} };
    try {
      const local = new MCPAuthServer({
        get: (key: string) => store.get(key),
        set: (key: string, value: unknown) => { store.set(key, value); },
      });
      await local.generatePassword();
      expect(calls).to.deep.equal(["addLogin"]);
    } finally {
      if (previous.Cc === undefined) delete scope.Cc; else scope.Cc = previous.Cc;
      if (previous.Ci === undefined) delete scope.Ci; else scope.Ci = previous.Ci;
    }
  });
});
