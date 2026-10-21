"use client";

import Link from "next/link";
import {useCallback, useEffect, useRef, useState} from "react";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
import {apiFetch} from "@/lib/icheck-api";
import {mappingApproval, mappingLabel, suggestedChoices, type MappingAsset, type MappingChoices, type MappingRow, type MappingView} from "@/lib/integration-mapping";

const message = (error: unknown) => error instanceof Error ? error.message : "Asset mapping could not be updated.";
const batchSize = 1000;

export function IntegrationMapping({path, epochRef}: {path: string; epochRef: {current: number}}) {
  const [view, setView] = useState<MappingView | null>(null);
  const [offset, setOffset] = useState(0); const [page, setPage] = useState(0); const [refresh, setRefresh] = useState(0);
  const [choices, setChoices] = useState<MappingChoices>({}); const [approved, setApproved] = useState(false);
  const [error, setError] = useState(""); const [notice, setNotice] = useState(""); const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<MappingRow | null>(null); const [search, setSearch] = useState("");
  const [candidates, setCandidates] = useState<MappingAsset[]>([]); const [truncated, setTruncated] = useState(false);
  const mounted = useRef(false); const requests = useRef(0); const submitting = useRef(false);
  const read = useCallback(async () => {
    const serial = epochRef.current, request = ++requests.current;
    const result = await apiFetch<MappingView>(`${path}/asset-mapping?limit=${batchSize}&offset=${offset}`);
    if (mounted.current && serial === epochRef.current && request === requests.current) {
      setView(result); setChoices({}); setApproved(false); setEditing(null); setCandidates([]); setPage(0);
    }
  }, [path, offset, epochRef]);
  useEffect(() => {
    mounted.current = true;
    const serial = epochRef.current, requestContext = requests;
    const timer = window.setTimeout(() => {void read().catch(error => {
      if (mounted.current && serial === epochRef.current) setError(message(error));
    });}, 0);
    return () => {mounted.current = false; requestContext.current++; window.clearTimeout(timer);};
  }, [read, refresh, epochRef]);
  async function save(payload: unknown) {
    if (submitting.current) return;
    const serial = epochRef.current; submitting.current = true; setBusy(true); setError(""); setNotice("");
    try {
      const result = await apiFetch<{updated: number}>(`${path}/asset-mapping`, {method: "PUT",
        headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)});
      if (mounted.current && serial === epochRef.current) {
        setNotice(`${result.updated} identity links updated. No assets, polling or investigations were created.`);
        await read();
      }
    } catch (error) {
      if (mounted.current && serial === epochRef.current) {
        setError(message(error)); setChoices({}); setApproved(false);
        await read().catch(() => {setView(null);});
      }
    } finally {if (mounted.current && serial === epochRef.current) {setBusy(false); submitting.current = false;}}
  }
  async function find() {
    if (submitting.current) return;
    const serial = epochRef.current; submitting.current = true; setBusy(true); setError("");
    try {
      const result = await apiFetch<{items: MappingAsset[]; truncated: boolean}>(`${path}/asset-candidates?search=${encodeURIComponent(search)}`);
      if (mounted.current && serial === epochRef.current) {setCandidates(result.items); setTruncated(result.truncated);}
    } catch (error) {if (mounted.current && serial === epochRef.current) setError(message(error));}
    finally {if (mounted.current && serial === epochRef.current) {setBusy(false); submitting.current = false;}}
  }
  function choose(row: MappingRow, asset: MappingAsset | null) {
    setChoices(current => {const next = {...current}; if (asset) next[row.resource_id] = asset; else delete next[row.resource_id]; return next;});
    setApproved(false);
  }
  const suggestions = view ? suggestedChoices(view) : {};
  const selected = Object.keys(choices).length;
  return <section className="rounded-xl border border-slate-200 bg-white p-5 sm:p-6">
    <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="font-semibold">Link source resources to existing assets</h2>
      <Button variant="outline" disabled={busy} onClick={() => {setView(null); setRefresh(n => n + 1);}}>Refresh mapping</Button></div>
    <p className="mt-2 text-sm text-slate-600">Review suggested links in bulk. Names are suggestions, not proof of identity. Linking reuses your existing assets; it does not add devices, copy credentials or start collection.</p>
    <p className="mt-2 text-xs text-slate-500">One asset per source resource, and one resource per asset within this connection. Ambiguous names stay unlinked. Enable the external alert feed separately; automatic investigation also needs an enabled AI policy.</p>
    {error && <p role="alert" className="mt-4 rounded bg-red-50 p-3 text-sm text-red-800">{error}</p>}
    {notice && <p role="status" className="mt-4 rounded bg-violet-50 p-3 text-sm">{notice}</p>}
    {!view ? <p role="status" className="mt-4">{error ? "Mapping unavailable. Try Refresh mapping." : "Loading asset mapping…"}</p> : <>
      {!view.can_link && <p className="mt-4 rounded bg-amber-50 p-3 text-sm">Enable the connection and complete an inventory sync before linking. Saved links can still be removed.</p>}
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <Button variant="outline" disabled={busy || !Object.keys(suggestions).length} onClick={() => {setChoices(suggestions); setApproved(false);}}>
          Select all {Object.keys(suggestions).length} suggested matches in this batch</Button>
        <Button variant="outline" disabled={busy || !selected} onClick={() => {setChoices({}); setApproved(false);}}>Clear selection</Button>
        <span className="text-sm">{selected} selected · Batch {view.total ? offset + 1 : 0}–{offset + view.items.length} of {view.total}</span>
      </div>
      <div className="mt-4 divide-y">{view.items.slice(page * 50, (page + 1) * 50).map(row => {
        const candidate = choices[row.resource_id] || row.suggestion;
        return <article key={row.resource_id} className="py-4">
          <div className="flex items-start gap-3">{candidate && row.current && <input className="mt-1" type="checkbox" aria-label={`Select link for ${row.name} (source ${row.remote_id})`}
            disabled={busy} checked={!!choices[row.resource_id]} onChange={event => choose(row, event.target.checked ? candidate : null)} />}
            <div className="min-w-0 flex-1"><h3 className="break-words font-medium">{row.name}</h3>
              <p className="mt-1 text-xs text-slate-500">Source ID {row.remote_id} · {mappingLabel(row)}</p>
              {row.device && <p className="mt-2 break-words text-sm">Saved link: <Link className="text-violet-700 underline" href={`/assets/devices?device=${encodeURIComponent(row.device.id)}`}>{row.device.name}</Link>{row.device.site && ` · ${row.device.site}`}</p>}
              {candidate && <p className="mt-2 break-words text-sm">{choices[row.resource_id] ? "Selected" : "Suggested"} asset: {candidate.name} · {candidate.management_ip || "No management address"}{candidate.site && ` · ${candidate.site}`}</p>}
              <div className="mt-3 flex flex-wrap gap-2"><Button variant="outline" disabled={busy || !row.current || !view.can_link} onClick={() => {
                setEditing(row); setSearch(row.name); setCandidates([]); setTruncated(false);
              }}>{row.device ? "Review or change link" : "Choose another asset"}</Button>
                {row.device && <Button variant="outline" disabled={busy} onClick={() => void save({expected_revision: view.connection_revision,
                  confirm: true, items: [{resource_id: row.resource_id, source_name: row.name, expected_binding_revision: row.binding_revision, device_id: null}]})}>Unlink asset</Button>}
              </div>
            </div></div>
        </article>;
      })}</div>
      {!view.items.length && <p className="mt-4 text-sm">No source resources to map. Import inventory first. Assets are created in Assets, not by this mapping page.</p>}
      {editing && <div className="mt-4 rounded-lg border border-violet-200 bg-violet-50 p-4">
        <h3 className="break-words font-medium">Choose asset for {editing.name} (source {editing.remote_id})</h3>
        <form className="mt-3 flex flex-wrap items-end gap-2" onSubmit={event => {event.preventDefault(); void find();}}>
          <label className="min-w-0 flex-1 text-sm">Asset name or management address<Input value={search} maxLength={128} required disabled={busy} onChange={event => setSearch(event.target.value)} /></label>
          <Button variant="outline" disabled={busy || !search.trim()}>Search assets</Button>
          <Button type="button" variant="outline" disabled={busy} onClick={() => setEditing(null)}>Cancel selection</Button>
        </form>
        {candidates.map(device => <div key={device.id} className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded border bg-white p-3">
          <span className="min-w-0 break-words text-sm">{device.name} · {device.management_ip || "No management address"}{device.site && ` · ${device.site}`}</span>
          <Button variant="outline" disabled={busy} onClick={() => {choose(editing, device); setEditing(null);}}>Use this asset</Button></div>)}
        {truncated && <p className="mt-2 text-xs">More matches exist. Narrow the search.</p>}
        <p className="mt-3 text-xs">Selection is local until you approve the batch below. Search never contacts a device.</p>
      </div>}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Button variant="outline" disabled={busy || !page} onClick={() => setPage(page - 1)}>Previous rows</Button>
        <span className="text-xs">Showing {view.items.length ? page * 50 + 1 : 0}–{Math.min((page + 1) * 50, view.items.length)} of {view.items.length} in this batch</span>
        <Button variant="outline" disabled={busy || (page + 1) * 50 >= view.items.length} onClick={() => setPage(page + 1)}>Next rows</Button>
      </div>
      <div className="mt-6 space-y-3 border-t pt-4">
        <label className="flex items-start gap-2 text-sm"><input type="checkbox" disabled={busy || !selected} checked={approved} onChange={event => setApproved(event.target.checked)} />
          I reviewed the {selected} selected resource-to-asset links in this batch.</label>
        <Button disabled={busy || !approved || !selected || !view.can_link} onClick={() => {
          try {void save(mappingApproval(view, choices));} catch (error) {setError(message(error));}
        }}>{busy ? "Saving…" : `Approve ${selected} links`}</Button>
        <p className="text-xs text-slate-500">A changed scan, scope, asset or saved link requires a fresh review. Unlinking removes only the association; it never deletes the asset or source history.</p>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        <Button variant="outline" disabled={busy || !offset || !!selected} onClick={() => {setView(null); setOffset(offset - batchSize);}}>Previous batch</Button>
        <Button variant="outline" disabled={busy || offset + batchSize >= view.total || !!selected} onClick={() => {setView(null); setOffset(offset + batchSize);}}>Next batch</Button>
      </div>
    </>}
  </section>;
}
