"use client";

import Link from "next/link";
import {useEffect, useState} from "react";
import {apiFetch, NAMESPACE_KEY, SESSION_CHANGE_KEY} from "@/lib/icheck-api";

type SavedDashboard = {change_id:string; connection_id:string; title:string; protocol:string; url:string; connection_enabled:boolean};
type DashboardLinks = {dashboards:SavedDashboard[]; has_more:boolean; boundary:string};

/** Saved Grafana links only: this component never queries metrics or renders charts. */
export function DeviceDashboards({deviceId, from="now-1h", to="now"}: {deviceId:string; from?:string; to?:string}) {
  const [links,setLinks]=useState<DashboardLinks|null>(null);
  const [error,setError]=useState("");
  useEffect(()=>{
    let active=true;
    const controller=new AbortController();
    setLinks(null);setError("");
    const reset=()=>{active=false;controller.abort();setLinks(null);setError("");};
    const storage=(event:StorageEvent)=>{if([NAMESPACE_KEY,SESSION_CHANGE_KEY,null].includes(event.key))reset();};
    window.addEventListener("storage",storage);
    window.addEventListener("icheck:namespace-changed",reset);
    apiFetch<DashboardLinks>(`/grafana/devices/${encodeURIComponent(deviceId)}/dashboards?`+
      new URLSearchParams({from,to}),{signal:controller.signal})
      .then(result=>{if(active){setLinks(result);setError("");}})
      .catch(cause=>{if(active)setError(cause instanceof Error?cause.message:"Saved dashboards could not be loaded.");});
    return()=>{active=false;controller.abort();window.removeEventListener("storage",storage);window.removeEventListener("icheck:namespace-changed",reset);};
  },[deviceId,from,to]);
  return <section className="rounded border bg-white p-3 text-xs" aria-label="Saved device dashboards">
    <h3 className="font-semibold">Saved Grafana dashboards</h3>
    {error?<p className="mt-2 text-muted-foreground">{error}</p>:links?<>
      {links.dashboards.length?links.dashboards.map(row=><p key={row.change_id} className="mt-2">
        <a href={row.url} className="text-violet-700 underline">{row.title}</a>
        {!row.connection_enabled?<span className="ml-2 text-muted-foreground">Connection disabled · historical context</span>:null}
      </p>):<p className="mt-2 text-muted-foreground">No saved target dashboard. <Link href="/studio" className="text-violet-700 underline">Create one in Capability Studio</Link>.</p>}
      <p className="mt-2 text-muted-foreground">Saved URLs carry the selected time range; opening one does not prove fresh measurements.</p>
      {links.has_more?<p className="mt-1 text-muted-foreground">Showing a bounded saved-dashboard list. Use Dashboards to inspect additional history.</p>:null}
    </>:<p className="mt-2 text-muted-foreground">Loading saved dashboard links…</p>}
  </section>;
}
