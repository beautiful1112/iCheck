"use client";
import {useState} from "react";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";
export function StudioRuntimeRestore({versions,currentVersion,disabled,onRestore}:{versions:{id:string;version:number;status:string}[];currentVersion:string;disabled:boolean;onRestore:(version:number,reason:string)=>Promise<void>}){
  const [source,setSource]=useState(""),[reason,setReason]=useState("");
  const choices=versions.filter(row=>row.id!==currentVersion&&["validated","published","deprecated"].includes(row.status)).sort((a,b)=>b.version-a.version);
  return <details className="rounded border p-3"><summary className="cursor-pointer text-sm">Prior versions and restore preview</summary>
    <p className="mt-2 text-xs">Prepare an earlier definition as a new draft in this conversation. Current dependencies are revalidated; existing published versions and in-flight runs remain unchanged.</p>
    <fieldset disabled={disabled} className="mt-3 space-y-3">
      <label className="block text-sm">Prior definition<select aria-label="Prior definition" className="mt-1 block w-full rounded border bg-white p-2 text-sm" value={source} onChange={event=>setSource(event.target.value)}>
        <option value="">Choose a retained version</option>{choices.map(row=><option key={row.id} value={row.version}>Version {row.version} · {row.status}</option>)}</select></label>
      <label className="block text-sm">Why restore this definition?<Input className="mt-1" value={reason} onChange={event=>setReason(event.target.value)} maxLength={4000}/></label>
      <Button type="button" variant="outline" disabled={!source||reason.trim().length<3||disabled} onClick={()=>void onRestore(Number(source),reason.trim())}>Preview prior definition</Button>
    </fieldset>
  </details>;
}
