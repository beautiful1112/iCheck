"use client";
import {useEffect,useState} from "react";
import {Input} from "@/components/ui/input";
import {Textarea} from "@/components/ui/textarea";
import {apiFetch} from "@/lib/icheck-api";
import {InputSchema,runtimeDocument,runtimeFields,setRuntimeField} from "@/lib/runtime-input";

export function RuntimeInputForm({schema,value,onChange,disabled,canReadDevices}:{schema:InputSchema;value:string;onChange:(value:string)=>void;disabled:boolean;canReadDevices:boolean}){
  const fields=runtimeFields(schema),usesDevices=fields.some(field=>["device_id","controller_id"].includes(field.name));
  const [devices,setDevices]=useState<{id:string;name:string;management_ip:string|null}[]>([]),[notice,setNotice]=useState("");
  useEffect(()=>{
    let active=true;
    if(usesDevices&&canReadDevices){void apiFetch<{id:string;name:string;management_ip:string|null}[]>("/assets/devices?limit=100")
      .then(rows=>{if(active)setDevices(rows);}).catch(()=>{if(active)setNotice("Device choices are unavailable. Use an authorized device reference in Advanced inputs.");});}
    return()=>{active=false;};
  },[usesDevices,canReadDevices]);
  let document:Record<string,unknown>|null=null;try{document=runtimeDocument(value);}catch{}
  const style="mt-1 w-full min-w-0 rounded border border-white/15 bg-slate-950 px-3 py-2 text-sm text-slate-100";
  return <div className="space-y-3 text-slate-200"><p className="text-xs font-semibold">Inputs for this check</p>
    {document&&fields.length>0&&<fieldset disabled={disabled} className="grid min-w-0 gap-3 sm:grid-cols-2">{fields.map(field=>{
      const current=document![field.name],deviceField=["device_id","controller_id"].includes(field.name)&&canReadDevices&&!field.choices.length;
      const choices=field.choices.length?field.choices:field.type==="boolean"?[true,false]:[];
      return <label key={field.name} className="min-w-0 text-xs">{field.label}{field.required?" *":" (optional)"}
        {deviceField?<select aria-label={field.label} className={style} value={typeof current==="string"?current:""} onChange={event=>onChange(setRuntimeField(value,field,event.target.value))}>
          <option value="">Select an authorized device</option>{devices.map(device=><option key={device.id} value={device.id}>{device.name}{device.management_ip?` · ${device.management_ip}`:""}</option>)}
          {typeof current==="string"&&!devices.some(device=>device.id===current)&&<option value={current}>{current} · supplied reference</option>}</select>:
          choices.length?<select aria-label={field.label} className={style} value={field.choices.length?(current===undefined?"":String(choices.indexOf(current))):current===undefined?"":String(current)}
              onChange={event=>onChange(setRuntimeField(value,field,event.target.value))}>
            <option value="">Choose a value</option>{choices.map((choice,index)=><option key={index} value={field.choices.length?index:String(choice)}>{String(choice)}</option>)}</select>:
          <Input className={style} type="text" inputMode={field.type==="number"||field.type==="integer"?"decimal":"text"} value={current===undefined?"":String(current)}
            maxLength={typeof field.schema.maxLength==="number"?field.schema.maxLength*2:4096} onChange={event=>onChange(setRuntimeField(value,field,event.target.value))}/>}
        {field.description&&<span className="mt-1 block text-[11px] text-slate-400">{field.description}</span>}
      </label>;
    })}</fieldset>}
    {notice&&<p className="text-xs text-amber-200">{notice}</p>}
    <p className="text-[11px] text-slate-400">Starting this check explicitly queues its saved version. It may contact approved read-only tools and use the configured AI budget. It does not activate a recurring trigger.</p>
    <details open={!document||!fields.length}><summary className="cursor-pointer text-xs">Advanced input JSON and schema</summary>
      <label className="mt-3 block text-xs">Typed check input<Textarea value={value} onChange={event=>onChange(event.target.value)} rows={5} spellCheck={false} disabled={disabled}
        className="mt-2 max-w-full border-white/15 bg-slate-950 font-mono text-xs text-slate-200"/></label>
      <p className="mt-2 text-xs text-slate-400">Use this for nested inputs or references outside the first 100 device choices. Enter references only, never raw credentials. The server validates the complete schema.</p>
      {!document&&<p role="alert" className="mt-2 text-xs text-red-300">Inputs must be valid JSON with an object at the root.</p>}
      <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(schema,null,2)}</pre>
    </details>
  </div>;
}
