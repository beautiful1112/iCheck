export const API_URL =
  process.env.NEXT_PUBLIC_ICHECK_API_URL || "http://localhost:8000/api/v1";

export class APIError extends Error {
  status: number;

  constructor(status: number, detail: string) {
    super(detail);
    this.name = "APIError";
    this.status = status;
  }
}

export class BrowserContextChangedError extends Error {
  constructor() {
    super("The browser session or tenant and region changed. Retry in the current workspace.");
    this.name = "BrowserContextChangedError";
  }
}

let csrfToken: string | null = null;
let csrfRequest: Promise<string> | null = null;
let csrfRequired: boolean | null = null;
let csrfRequirementRequest: Promise<boolean> | null = null;
let contextRevision = 0;
let sessionExpiredNotified = false;
const activeStreamClosers = new Set<() => void>();
export const NAMESPACE_KEY = "icheck.namespace.v1";
export const SESSION_CHANGE_KEY = "icheck.browser-session-change.v1";

export type ApiNamespace = {
  tenantId: string;
  regionId: string;
};

type RequestContext = {
  namespace: ApiNamespace | null;
  revision: number;
  sessionChange: string | null;
};

let observedNamespace = getApiNamespace();
let observedSessionChange = sessionChangeValue();

function sameNamespace(left: ApiNamespace | null, right: ApiNamespace | null): boolean {
  return left?.tenantId === right?.tenantId && left?.regionId === right?.regionId;
}

function contextChanged(): BrowserContextChangedError {
  return new BrowserContextChangedError();
}

function invalidateRequestContext(): void {
  contextRevision += 1;
  csrfToken = null;
  csrfRequest = null;
  csrfRequired = null;
  csrfRequirementRequest = null;
  for (const close of activeStreamClosers) close();
}

if (typeof window !== "undefined") {
  window.addEventListener("storage", (event) => {
    if (event.key === NAMESPACE_KEY || event.key === SESSION_CHANGE_KEY || event.key === null) {
      invalidateRequestContext();
      observedNamespace = getApiNamespace();
      observedSessionChange = sessionChangeValue();
    }
  });
}

function requestContext(): RequestContext {
  const namespace = getApiNamespace();
  const sessionChange = sessionChangeValue();
  if (!sameNamespace(namespace, observedNamespace) || sessionChange !== observedSessionChange) {
    throw contextChanged();
  }
  return {
    namespace,
    revision: contextRevision,
    sessionChange,
  };
}

function sessionChangeValue(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(SESSION_CHANGE_KEY);
  } catch {
    return null;
  }
}

function assertRequestContext(context: RequestContext): void {
  const current = getApiNamespace();
  if (
    context.revision !== contextRevision ||
    context.sessionChange !== sessionChangeValue() ||
    !sameNamespace(context.namespace, current)
  ) {
    throw contextChanged();
  }
}

export function announceBrowserSessionChange(reason: "login" | "logout" | "expired"): void {
  invalidateRequestContext();
  sessionExpiredNotified = reason === "expired";
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(
      SESSION_CHANGE_KEY,
      reason + ":" + Date.now() + ":" + Math.random(),
    );
    observedSessionChange = sessionChangeValue();
  } catch {
    // A disabled storage provider cannot broadcast to other tabs.
  }
}

function requireLogin(): void {
  if (typeof window === "undefined" || window.location.pathname === "/login") return;
  if (!sessionExpiredNotified) announceBrowserSessionChange("expired");
  window.location.assign("/login");
}

export type OIDCFederationConfig = {
  enabled: boolean;
  display_name: string | null;
  start_url: string | null;
  local_token_login_enabled: boolean;
};

export type PasswordLoginConfig = { enabled: boolean };

export async function getPasswordLoginConfig(): Promise<PasswordLoginConfig> {
  const response = await fetch(API_URL + "/auth/login/config", { credentials: "include" });
  if (!response.ok) throw new APIError(response.status, await responseDetail(response));
  return response.json() as Promise<PasswordLoginConfig>;
}

export type TrustedProxyFederationConfig = {
  enabled: boolean;
  display_name: string | null;
  start_url: string | null;
};

export async function getOIDCFederationConfig(): Promise<OIDCFederationConfig> {
  const response = await fetch(API_URL + "/auth/oidc/config", {
    credentials: "include",
  });
  if (!response.ok) {
    throw new APIError(response.status, await responseDetail(response));
  }
  return response.json() as Promise<OIDCFederationConfig>;
}

export async function getTrustedProxyFederationConfig(): Promise<TrustedProxyFederationConfig> {
  const response = await fetch(API_URL + "/auth/trusted-proxy/config", {
    credentials: "include",
  });
  if (!response.ok) {
    throw new APIError(response.status, await responseDetail(response));
  }
  return response.json() as Promise<TrustedProxyFederationConfig>;
}

export function beginOIDCLogin(startUrl: string, returnTo = "/auth/complete"): void {
  const separator = startUrl.includes("?") ? "&" : "?";
  window.location.assign(
    API_URL + startUrl + separator + "return_to=" + encodeURIComponent(returnTo),
  );
}

export function beginTrustedProxyLogin(
  startUrl: string,
  returnTo = "/auth/complete",
): void {
  const separator = startUrl.includes("?") ? "&" : "?";
  window.location.assign(
    API_URL + startUrl + separator + "return_to=" + encodeURIComponent(returnTo),
  );
}

export function beginMCPOAuth(
  serverId: string,
  returnTo = "/settings/mcp",
  scopeChallengeId?: string,
): void {
  const challenge = scopeChallengeId
    ? "&scope_challenge_id=" + encodeURIComponent(scopeChallengeId)
    : "";
  window.location.assign(
    API_URL +
      "/mcp/servers/" +
      encodeURIComponent(serverId) +
      "/oauth/start?return_to=" +
      encodeURIComponent(returnTo) +
      challenge,
  );
}

export function getApiNamespace(): ApiNamespace | null {
  if (typeof window === "undefined") return null;
  try {
    const value = JSON.parse(
      window.localStorage.getItem(NAMESPACE_KEY) || "null",
    ) as Partial<ApiNamespace> | null;
    if (!value?.tenantId || !value.regionId) return null;
    return { tenantId: value.tenantId, regionId: value.regionId };
  } catch {
    return null;
  }
}

export function setApiNamespace(namespace: ApiNamespace): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(NAMESPACE_KEY, JSON.stringify(namespace));
  observedNamespace = namespace;
  invalidateRequestContext();
  window.dispatchEvent(new CustomEvent("icheck:namespace-changed"));
}

export function clearApiNamespace(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(NAMESPACE_KEY);
  } catch {
    // Session cleanup still applies when browser storage is unavailable.
  }
  observedNamespace = getApiNamespace();
  invalidateRequestContext();
  window.dispatchEvent(new CustomEvent("icheck:namespace-changed"));
}

function namespaceHeaders(headers: Headers, namespace: ApiNamespace | null): Headers {
  if (namespace) {
    headers.set("X-Icheck-Tenant-ID", namespace.tenantId);
    headers.set("X-Icheck-Region-ID", namespace.regionId);
  }
  return headers;
}

async function responseDetail(response: Response): Promise<string> {
  const fallback = response.status + " " + response.statusText;
  try {
    const document = (await response.json()) as {
      detail?: string | Array<{ msg?: string }>;
    };
    if (Array.isArray(document.detail)) {
      return document.detail
        .map((item) => item.msg || "Validation failed")
        .join("; ");
    }
    return document.detail || fallback;
  } catch {
    return fallback;
  }
}

async function refreshCsrf(context: RequestContext): Promise<string> {
  assertRequestContext(context);
  if (!csrfRequest) {
    const request = fetch(
      API_URL + "/auth/browser-sessions/current/csrf",
      { credentials: "include", headers: namespaceHeaders(new Headers(), context.namespace) },
    )
      .then(async (response) => {
        assertRequestContext(context);
        if (!response.ok) {
          if (response.status === 401) requireLogin();
          throw new APIError(response.status, await responseDetail(response));
        }
        const document = (await response.json()) as { csrf_token: string };
        assertRequestContext(context);
        csrfToken = document.csrf_token;
        return document.csrf_token;
      })
      .finally(() => {
        if (csrfRequest === request) csrfRequest = null;
      });
    csrfRequest = request;
  }
  const token = await csrfRequest;
  assertRequestContext(context);
  return token;
}

async function requireCsrfForMutation(context: RequestContext): Promise<void> {
  assertRequestContext(context);
  if (csrfToken || csrfRequired === false) return;
  if (csrfRequired === null) {
    if (!csrfRequirementRequest) {
      const request = fetch(API_URL + "/auth/me", {
        credentials: "include",
        headers: namespaceHeaders(new Headers(), context.namespace),
      })
        .then(async (response) => {
          assertRequestContext(context);
          if (!response.ok) {
            if (response.status === 401) requireLogin();
            throw new APIError(response.status, await responseDetail(response));
          }
          const principal = (await response.json()) as { auth_method: string };
          assertRequestContext(context);
          csrfRequired = principal.auth_method === "browser_session";
          return csrfRequired;
        })
        .finally(() => {
          if (csrfRequirementRequest === request) csrfRequirementRequest = null;
        });
      csrfRequirementRequest = request;
    }
    await csrfRequirementRequest;
    assertRequestContext(context);
  }
  if (csrfRequired) await refreshCsrf(context);
}

async function apiResponse(
  path: string,
  init: RequestInit,
  context: RequestContext,
): Promise<Response> {
  const method = (init.method || "GET").toUpperCase();
  const unsafe = ["POST", "PUT", "PATCH", "DELETE"].includes(method);
  if (unsafe) await requireCsrfForMutation(context);
  assertRequestContext(context);
  const csrf = unsafe ? csrfToken : null;
  const headers = new Headers(init.headers);
  namespaceHeaders(headers, context.namespace);
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  if (csrf) headers.set("X-Icheck-CSRF-Token", csrf);

  let response = await fetch(API_URL + path, {
    ...init,
    headers,
    credentials: "include",
  });
  assertRequestContext(context);
  if (unsafe && response.status === 403) {
    const detail = await responseDetail(response);
    assertRequestContext(context);
    if (detail.includes("CSRF")) {
      csrfToken = null;
      headers.set("X-Icheck-CSRF-Token", await refreshCsrf(context));
      assertRequestContext(context);
      response = await fetch(API_URL + path, {
        ...init,
        headers,
        credentials: "include",
      });
      assertRequestContext(context);
    } else {
      throw new APIError(response.status, detail);
    }
  }
  if (!response.ok) {
    const detail = await responseDetail(response);
    assertRequestContext(context);
    if (response.status === 401) requireLogin();
    throw new APIError(response.status, detail);
  }
  return response;
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const context = requestContext();
  const response = await apiResponse(path, init, context);
  assertRequestContext(context);
  if (response.status === 204) return undefined as T;
  const document = await response.json() as T;
  assertRequestContext(context);
  return document;
}

export async function apiBlob(path: string): Promise<{
  blob: Blob; snapshotSha256: string | null; contentSha256: string | null;
}> {
  const context = requestContext();
  const response = await apiResponse(path, { cache: "no-store" }, context);
  const blob = await response.blob();
  assertRequestContext(context);
  return {
    blob,
    snapshotSha256: response.headers.get("X-Icheck-Snapshot-SHA256"),
    contentSha256: response.headers.get("X-Icheck-Content-SHA256"),
  };
}

export async function exchangeAccessToken(
  accessToken: string,
): Promise<void> {
  const response = await fetch(API_URL + "/auth/browser-sessions", {
    method: "POST",
    headers: { Authorization: "Bearer " + accessToken },
    credentials: "include",
  });
  if (!response.ok) {
    throw new APIError(response.status, await responseDetail(response));
  }
  const document = (await response.json()) as { csrf_token: string };
  announceBrowserSessionChange("login");
  clearApiNamespace();
  csrfToken = document.csrf_token;
}

export async function signInWithPassword(username: string, password: string): Promise<void> {
  const response = await fetch(API_URL + "/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ username: username.trim(), password }),
  });
  if (!response.ok) throw new APIError(response.status, await responseDetail(response));
  const document = await response.json() as { csrf_token: string };
  announceBrowserSessionChange("login");
  clearApiNamespace();
  csrfToken = document.csrf_token;
}

export async function changeOwnPassword(currentPassword: string, newPassword: string): Promise<void> {
  const document = await apiFetch<{ csrf_token: string }>("/auth/password/change", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
  announceBrowserSessionChange("login");
  clearApiNamespace();
  csrfToken = document.csrf_token;
}

export async function closeBrowserSession(): Promise<void> {
  await apiFetch<void>("/auth/browser-sessions/current", { method: "DELETE" });
  announceBrowserSessionChange("logout");
  clearApiNamespace();
}

export type AuthenticatedEventStream = {
  addEventListener: (type: string, listener: (event: MessageEvent<string>) => void) => void;
  close: () => void;
};

export function authenticatedEventSource(path: string): AuthenticatedEventStream {
  const context = requestContext();
  const namespace = context.namespace;
  const separator = path.includes("?") ? "&" : "?";
  const scopedPath = namespace
    ? path + separator + "icheck_tenant_id=" + encodeURIComponent(namespace.tenantId) +
      "&icheck_region_id=" + encodeURIComponent(namespace.regionId)
    : path;
  const source = new EventSource(API_URL + scopedPath, { withCredentials: true });
  try {
    assertRequestContext(context);
  } catch (error) {
    source.close();
    throw error;
  }
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    activeStreamClosers.delete(close);
    source.close();
  };
  activeStreamClosers.add(close);
  return {
    addEventListener(type, listener) {
      if (closed) return;
      source.addEventListener(type, (event) => {
        if (closed) return;
        try {
          assertRequestContext(context);
        } catch {
          close();
          return;
        }
        listener(event as MessageEvent<string>);
      });
    },
    close,
  };
}
