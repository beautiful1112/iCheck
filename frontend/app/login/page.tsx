"use client";

import { useEffect, useState } from "react";
import {
  Building2,
  LockKeyhole,
  UserRound,
  Loader2,
  Network,
  ShieldCheck,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  beginOIDCLogin,
  beginTrustedProxyLogin,
  signInWithPassword,
  getPasswordLoginConfig,
  getOIDCFederationConfig,
  getTrustedProxyFederationConfig,
  type OIDCFederationConfig,
  type TrustedProxyFederationConfig,
  type PasswordLoginConfig,
} from "@/lib/icheck-api";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfig, setPasswordConfig] = useState<PasswordLoginConfig | null>(null);
  const [loading, setLoading] = useState(false);
  const [config, setConfig] = useState<OIDCFederationConfig | null>(null);
  const [proxyConfig, setProxyConfig] =
    useState<TrustedProxyFederationConfig | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const oidcError = new URLSearchParams(window.location.search).get(
      "oidc_error",
    );
    const proxyError = new URLSearchParams(window.location.search).get(
      "proxy_error",
    );
    Promise.all([
      getPasswordLoginConfig(),
      getOIDCFederationConfig(),
      getTrustedProxyFederationConfig(),
    ])
      .then(([nextPasswordConfig, nextConfig, nextProxyConfig]) => {
        setPasswordConfig(nextPasswordConfig);
        setConfig(nextConfig);
        setProxyConfig(nextProxyConfig);
        if (oidcError) {
          setError(
            oidcError === "identity_not_enrolled"
              ? "Your enterprise identity is not enrolled or has been disabled."
              : "Enterprise sign-in could not be completed.",
          );
        } else if (proxyError) {
          setError(
            proxyError === "identity_not_enrolled"
              ? "Your gateway identity is not enrolled or has been disabled."
              : "Identity-gateway sign-in could not be completed.",
          );
        }
      })
      .catch((caught) => {
        setError(
          caught instanceof Error
            ? caught.message
            : "Unable to load sign-in policy",
        );
      });
  }, []);

  async function signIn(event: React.FormEvent) {
    event.preventDefault();
    if (!username.trim() || !password) return;
    setLoading(true);
    setError(null);
    try {
      await signInWithPassword(username, password);
      setPassword("");
      window.location.assign("/");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to sign in");
    } finally {
      setPassword("");
      setLoading(false);
    }
  }

  return (
    <main className="grid min-h-screen place-items-center bg-[#f5f6f8] px-4 text-slate-900">
      <section className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-7 shadow-sm">
        <div className="grid size-11 place-items-center rounded-xl bg-violet-50 text-violet-700">
          <ShieldCheck className="size-5" />
        </div>
        <h1 className="mt-5 text-xl font-semibold tracking-tight">
          Sign in to iCheck
        </h1>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">
          {passwordConfig && !passwordConfig.enabled
            ? "Use your organization’s sign-in to open your workspace."
            : "Use your username and password to open your workspace."}
        </p>
        {passwordConfig?.enabled ? (
          <form
            className="mt-6 space-y-4"
            onSubmit={signIn}
          >
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-600">
                Username
              </span>
              <div className="relative">
                <UserRound className="pointer-events-none absolute left-3 top-3 size-4 text-muted-foreground" />
                <Input
                  name="username"
                  autoComplete="username"
                  required
                  maxLength={255}
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  className="pl-9"
                />
              </div>
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-600">Password</span>
              <div className="relative">
                <LockKeyhole className="pointer-events-none absolute left-3 top-3 size-4 text-muted-foreground" />
                <Input name="password" type="password" autoComplete="current-password"
                  required maxLength={256} value={password}
                  onChange={(event) => setPassword(event.target.value)} className="pl-9" />
              </div>
            </label>
            {error ? (
              <p role="alert" className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">
                {error}
              </p>
            ) : null}
            <Button className="w-full" disabled={loading || !username.trim() || !password}>
              {loading ? <Loader2 className="size-4 animate-spin" /> : null}
              Sign in
            </Button>
          </form>
        ) : null}
        {(config?.enabled || proxyConfig?.enabled) && passwordConfig?.enabled ? (
          <div className="my-5 flex items-center gap-3 text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            <span className="h-px flex-1 bg-slate-200" />
            Or continue with single sign-on
            <span className="h-px flex-1 bg-slate-200" />
          </div>
        ) : null}
        {config?.enabled && config.start_url ? (
          <Button type="button" variant={passwordConfig?.enabled ? "outline" : "default"}
            className={passwordConfig?.enabled ? "w-full" : "mt-6 w-full"}
            onClick={() => beginOIDCLogin(config.start_url || "/auth/oidc/start")}>
            <Building2 className="size-4" />
            Continue with {config.display_name || "enterprise SSO"}
          </Button>
        ) : null}
        {proxyConfig?.enabled && proxyConfig.start_url ? (
          <Button type="button" variant={passwordConfig?.enabled || config?.enabled ? "outline" : "default"}
            className={config?.enabled ? "mt-3 w-full" : "mt-6 w-full"}
            onClick={() => beginTrustedProxyLogin(proxyConfig.start_url || "/auth/trusted-proxy/callback")}>
            <Network className="size-4" />
            Continue with {proxyConfig.display_name || "identity gateway"}
          </Button>
        ) : null}
        {config &&
        proxyConfig &&
        !config.enabled &&
        !proxyConfig.enabled &&
        passwordConfig && !passwordConfig.enabled ? (
          <p className="mt-6 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-800">
            Browser sign-in is not enabled. Contact the platform administrator.
          </p>
        ) : null}
        {(!config || !proxyConfig || !passwordConfig) && !error ? (
          <div className="mt-6 flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" />
            Loading sign-in policy…
          </div>
        ) : null}
        {error && !passwordConfig?.enabled ? (
          <p className="mt-5 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">
            {error}
          </p>
        ) : null}
      </section>
    </main>
  );
}
