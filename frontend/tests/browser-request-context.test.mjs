import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";

let nextCase = 0;

function deferred() {
  let resolve;
  const promise = new Promise((ready) => { resolve = ready; });
  return { promise, resolve };
}

async function browser(t, fetcher, EventSourceClass) {
  const previous = {
    window: globalThis.window,
    fetch: globalThis.fetch,
    CustomEvent: globalThis.CustomEvent,
    EventSource: globalThis.EventSource,
  };
  const values = new Map();
  const listeners = new Map();
  const destinations = [];
  globalThis.window = {
    localStorage: {
      getItem: (key) => values.get(key) ?? null,
      setItem: (key, value) => values.set(key, value),
      removeItem: (key) => values.delete(key),
    },
    location: { pathname: "/", assign: (path) => destinations.push(path) },
    addEventListener: (name, listener) => {
      listeners.set(name, [...(listeners.get(name) || []), listener]);
    },
    dispatchEvent: (event) => {
      for (const listener of listeners.get(event.type) || []) listener(event);
    },
  };
  globalThis.CustomEvent = class { constructor(type) { this.type = type; } };
  globalThis.fetch = fetcher;
  if (EventSourceClass) globalThis.EventSource = EventSourceClass;
  t.after(() => {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete globalThis[name];
      else globalThis[name] = value;
    }
  });
  const path = new URL("../lib/icheck-api.ts", import.meta.url);
  path.searchParams.set("test", String(++nextCase));
  return { api: await import(path.href), values, destinations };
}

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const first = { tenantId: "tenant-a", regionId: "region-a" };
const second = { tenantId: "tenant-b", regionId: "region-b" };

test("protected backup blobs carry namespace and cookie context without caching or exposing bodies", async t => {
  let request;
  const {api}=await browser(t, async (url,init) => {request={url,init};return new Response("synthetic backup",{headers:{"Content-Type":"application/octet-stream"}});});
  api.setApiNamespace(first);
  const result=await api.apiBlob("/capability-studio/configuration-backups/fixture/download");
  assert.equal(result.blob.size,16);
  assert.equal(request.init.credentials,"include");
  assert.equal(request.init.cache,"no-store");
  assert.equal(new Headers(request.init.headers).get("X-Icheck-Tenant-ID"),first.tenantId);
  assert.equal(new Headers(request.init.headers).get("X-Icheck-Region-ID"),first.regionId);
  assert.equal(new Headers(request.init.headers).get("Authorization"),null);
});

test("a backup download is discarded if workspace changes while its body is arriving", async t => {
  const pending=deferred();
  const {api}=await browser(t,async()=>({ok:true,status:200,headers:new Headers(),blob:()=>pending.promise}));
  api.setApiNamespace(first);
  const download=api.apiBlob("/capability-studio/configuration-backups/fixture/download");
  const rejected=assert.rejects(download,api.BrowserContextChangedError);
  await new Promise(resolve=>setTimeout(resolve,0));
  api.setApiNamespace(second);
  pending.resolve(new Blob(["synthetic backup"]));
  await rejected;
});

test("password sign-in sends JSON credentials once and stores neither password nor API token", async (t) => {
  const calls = [];
  const password = "  A browser test passphrase!  ";
  const { api, values } = await browser(t, async (url, init = {}) => {
    calls.push({ url, init });
    if (url.endsWith("/auth/login")) return response({ csrf_token: "new-password-csrf" }, 201);
    if (url.endsWith("/auth/me")) return response({ auth_method: "browser_session" });
    return response({ ok: true });
  });
  api.setApiNamespace(first);
  await api.signInWithPassword(" admin ", password);
  assert.equal(calls[0].url.endsWith("/auth/login"), true);
  assert.equal(calls[0].init.credentials, "include");
  assert.deepEqual(JSON.parse(calls[0].init.body), { username: "admin", password });
  assert.equal(calls[0].init.headers["Content-Type"], "application/json");
  assert.equal(calls[0].init.headers.Authorization, undefined);
  assert.equal(values.has(api.NAMESPACE_KEY), false);
  assert.equal([...values.values()].some(value => value.includes(password)), false);
  await api.apiFetch("/assets/devices", { method: "POST", body: "{}" });
  assert.equal(new Headers(calls.at(-1).init.headers).get("X-Icheck-CSRF-Token"), "new-password-csrf");
});

test("rejected password sign-in leaves browser identity and namespace unchanged", async (t) => {
  const { api, values, destinations } = await browser(t, async () => response({ detail: "Invalid username or password" }, 401));
  api.setApiNamespace(first);
  const before = [...values.entries()];
  await assert.rejects(api.signInWithPassword("admin", "wrong"), /Invalid username or password/);
  assert.deepEqual([...values.entries()], before);
  assert.deepEqual(destinations, []);
});

test("incorrect current password does not expire the browser session", async (t) => {
  const { api, destinations } = await browser(t, async (url) => {
    if (url.endsWith("/auth/me")) return response({ auth_method: "browser_session" });
    if (url.endsWith("/csrf")) return response({ csrf_token: "current-csrf" });
    return response({ detail: "Current password is incorrect" }, 400);
  });
  await assert.rejects(api.changeOwnPassword("wrong", "A new browser passphrase"), /Current password is incorrect/);
  assert.deepEqual(destinations, []);
});

test("default GUI has username/password and password-manager hints, never an API token input", () => {
  const source = readFileSync(new URL("../app/login/page.tsx", import.meta.url), "utf8");
  assert.match(source, /autoComplete="username"/);
  assert.match(source, /autoComplete="current-password"/);
  assert.match(source, /signInWithPassword\(username, password\)/);
  assert.doesNotMatch(source, /exchangeAccessToken|Control-plane access token|icp_…/);
});

function fakeEventSource() {
  const sources = [];
  class FakeEventSource {
    constructor(url, options) {
      this.url = url;
      this.options = options;
      this.listeners = new Map();
      this.closeCount = 0;
      sources.push(this);
    }

    addEventListener(type, listener) {
      this.listeners.set(type, [...(this.listeners.get(type) || []), listener]);
    }

    emit(type, data) {
      for (const listener of this.listeners.get(type) || []) listener({ data });
    }

    close() { this.closeCount += 1; }
  }
  return { sources, FakeEventSource };
}

test("a mutation waiting for authentication cannot cross into a new namespace", async (t) => {
  const auth = deferred();
  const requests = [];
  const { api } = await browser(t, (url, init) => {
    requests.push({ url, init });
    if (url.endsWith("/auth/me")) return auth.promise;
    return Promise.resolve(response({ created: true }));
  });
  api.setApiNamespace(first);
  const pending = api.apiFetch("/actions", { method: "POST", body: "{}" });
  api.setApiNamespace(second);
  auth.resolve(response({ auth_method: "bearer" }));
  await assert.rejects(pending, /tenant and region changed/);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].init.headers.get("X-Icheck-Tenant-ID"), first.tenantId);
});

test("storage changes block a click before the receiving tab gets its event", async (t) => {
  const requests = [];
  const { api, values } = await browser(t, async (url) => {
    requests.push(url);
    return response({ created: true });
  });
  api.setApiNamespace(first);
  values.set(api.NAMESPACE_KEY, JSON.stringify(second));
  await assert.rejects(api.apiFetch("/actions", { method: "POST", body: "{}" }), /tenant and region changed/);
  assert.equal(requests.length, 0);
  values.set(api.NAMESPACE_KEY, JSON.stringify(first));
  values.set(api.SESSION_CHANGE_KEY, "login:another-tab");
  await assert.rejects(api.apiFetch("/devices"), /browser session or tenant/);
  assert.equal(requests.length, 0);
});

test("a completed read cannot publish an older namespace body", async (t) => {
  const body = deferred();
  const parsing = deferred();
  const { api } = await browser(t, async () => ({
    ok: true, status: 200, json: () => { parsing.resolve(); return body.promise; },
  }));
  api.setApiNamespace(first);
  const pending = api.apiFetch("/devices");
  await parsing.promise;
  api.setApiNamespace(second);
  body.resolve({ items: [{ name: "old tenant device" }] });
  await assert.rejects(pending, /tenant and region changed/);
});

test("a session change rejects an in-flight body before storage events arrive", async (t) => {
  const body = deferred();
  const parsing = deferred();
  const { api, values } = await browser(t, async () => ({
    ok: true, status: 200, json: () => { parsing.resolve(); return body.promise; },
  }));
  const pending = api.apiFetch("/agent/investigations");
  await parsing.promise;
  values.set(api.SESSION_CHANGE_KEY, "logout:another-tab");
  body.resolve({ items: [{ title: "previous operator" }] });
  await assert.rejects(pending, /browser session or tenant/);
});

test("an expired browser session signals other tabs and routes to sign-in", async (t) => {
  const { api, values, destinations } = await browser(t, async () => response({ detail: "Expired" }, 401));
  await assert.rejects(api.apiFetch("/devices"), (error) => error.status === 401);
  assert.equal(destinations.at(-1), "/login");
  assert.match(values.get(api.SESSION_CHANGE_KEY), /^expired:/);
});

test("enterprise login callbacks return through the browser session boundary", async (t) => {
  const { api, destinations } = await browser(t, async () => response({}));
  api.beginOIDCLogin("/auth/oidc/start");
  api.beginTrustedProxyLogin("/auth/trusted-proxy/callback");
  assert.deepEqual(destinations, [
    "http://localhost:8000/api/v1/auth/oidc/start?return_to=%2Fauth%2Fcomplete",
    "http://localhost:8000/api/v1/auth/trusted-proxy/callback?return_to=%2Fauth%2Fcomplete",
  ]);
});

test("a live event cannot publish an old tenant after storage changes but before its event", async (t) => {
  const { sources, FakeEventSource } = fakeEventSource();
  const { api, values } = await browser(t, async () => response({}), FakeEventSource);
  api.setApiNamespace(first);
  const stream = api.authenticatedEventSource("/agent/executions/one/events/stream?after_sequence=7");
  const received = [];
  stream.addEventListener("execution.event", (event) => received.push(event.data));
  assert.equal(sources[0].options.withCredentials, true);
  assert.match(sources[0].url, /after_sequence=7&icheck_tenant_id=tenant-a&icheck_region_id=region-a$/);
  sources[0].emit("execution.event", "current tenant");
  values.set(api.NAMESPACE_KEY, JSON.stringify(second));
  assert.throws(() => api.authenticatedEventSource("/events/stream"), /tenant and region changed/);
  assert.equal(sources.length, 1);
  sources[0].emit("execution.event", "old tenant after switch");
  assert.deepEqual(received, ["current tenant"]);
  assert.equal(sources[0].closeCount, 1);
  stream.close();
  assert.equal(sources[0].closeCount, 1);
});

test("scope and session invalidation close live event connections immediately", async (t) => {
  const { sources, FakeEventSource } = fakeEventSource();
  const { api, values } = await browser(t, async () => response({}), FakeEventSource);
  api.setApiNamespace(first);
  api.authenticatedEventSource("/events/stream");
  api.setApiNamespace(second);
  assert.equal(sources[0].closeCount, 1);

  api.authenticatedEventSource("/events/stream");
  api.announceBrowserSessionChange("logout");
  assert.equal(sources[1].closeCount, 1);

  const pending = api.authenticatedEventSource("/events/stream");
  pending.addEventListener("stream.end", () => assert.fail("Old session event was delivered"));
  values.set(api.SESSION_CHANGE_KEY, "login:another-tab");
  sources[2].emit("stream.end", "stale session");
  assert.equal(sources[2].closeCount, 1);

  window.dispatchEvent({ type: "storage", key: api.SESSION_CHANGE_KEY });
  api.authenticatedEventSource("/events/stream");
  values.set(api.SESSION_CHANGE_KEY, "logout:another-tab");
  window.dispatchEvent({ type: "storage", key: api.SESSION_CHANGE_KEY });
  assert.equal(sources[3].closeCount, 1);
});
