"use client";

import {useCallback, useEffect, useRef, useState} from "react";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";
import {permits, validReference, type Capability, type StudioPrincipal, type StudioSession} from "@/lib/studio-builder";
import type {ExtensionInstallation, RegisteredTool, ExternalServer} from "@/lib/studio-library";

type Catalog = {principal: StudioPrincipal | null; artifacts: Capability[]; sessions: StudioSession[];
  extensions: ExtensionInstallation[] | null; tools: RegisteredTool[]; servers: ExternalServer[]; warnings: string[]};
const empty: Catalog = {principal: null, artifacts: [], sessions: [], extensions: null, tools: [], servers: [], warnings: []};
export function useStudioCatalog(mode: "library" | "conversations" | "mcp") {
  const [data, setData] = useState<Catalog>(empty), [loading, setLoading] = useState(true);
  const epoch = useRef(0), serial = useRef(0);
  const reload = useCallback(async () => {
    const context = epoch.current, request = ++serial.current;
    setLoading(true);
    const warnings: string[] = [];
    async function read<T>(path: string, allowed: boolean, fallback: T, label: string): Promise<T> {
      if (!allowed) {warnings.push(`${label}: you do not have permission to view this information.`); return fallback;}
      try {return await apiFetch<T>(path);}
      catch {warnings.push(`${label} could not be loaded. Refresh to retry.`); return fallback;}
    }
    let next: Catalog = {...empty, warnings};
    try {
      const principal = await apiFetch<StudioPrincipal>("/auth/me");
      const global = Boolean(principal.authorization_scope.all);
      if (mode === "conversations") {
        const sessions = await read<StudioSession[]>("/capability-studio/sessions?limit=500", global && permits(principal, "capabilities.read"), [], "Conversations");
        if (sessions.length === 500) warnings.push("Showing the latest 500 conversations. Older conversations remain accessible through their saved links.");
        next = {...empty, principal, sessions, warnings};
      } else {
        const artifactId = new URLSearchParams(window.location.search).get("artifact");
        const artifactsPromise = mode === "mcp" ? validReference(artifactId)
          ? read<Capability | null>(`/artifacts/${artifactId}`, permits(principal, "capabilities.read"), null, "MCP package").then(row => row ? [row] : [])
          : Promise.resolve([]) : read<Capability[]>("/artifacts?limit=1000", permits(principal, "capabilities.read"), [], "Capability packages");
        const [artifacts, runtime, tools, servers] = await Promise.all([
          artifactsPromise,
          read<{items: ExtensionInstallation[]} | null>("/capability-studio/extensions", global && permits(principal, "capabilities.manage"), null, "MCP installation status"),
          mode === "library" ? read<RegisteredTool[]>("/agent/tools?limit=1000", permits(principal, "investigations.read"), [], "Registered tools") : Promise.resolve([]),
          mode === "library" ? read<ExternalServer[]>("/mcp/servers?limit=1000", global && permits(principal, "tools.admin"), [], "External MCP connections") : Promise.resolve([]),
        ]);
        if ([artifacts.length, tools.length, servers.length].includes(1000)) warnings.push("A registry reached its 1,000-item display limit; counts reflect loaded entries only.");
        if (runtime?.items.length === 200) warnings.push("Installation status reached its 200-entry limit; missing installations are shown as unknown.");
        next = {...empty, principal, artifacts, extensions: runtime && runtime.items.length < 200 ? runtime.items : null, tools, servers, warnings};
      }
    } catch {warnings.push("Unable to load your account. Sign in again or refresh.");}
    if (context === epoch.current && request === serial.current) {setData(next); setLoading(false);}
  }, [mode]);
  useEffect(() => {
    const reset = () => {epoch.current++; serial.current++; setData(empty); void reload();};
    const storage = (event: StorageEvent) => {if ([NAMESPACE_KEY, SESSION_CHANGE_KEY, null].includes(event.key)) reset();};
    const timer = window.setTimeout(() => void reload(), 0);
    window.addEventListener("icheck:namespace-changed", reset); window.addEventListener("storage", storage);
    return () => {epoch.current++; window.clearTimeout(timer); window.removeEventListener("icheck:namespace-changed", reset); window.removeEventListener("storage", storage);};
  }, [reload]);
  return {...data, loading, reload};
}
