"use client";
import Link from "next/link";
import {FormEvent,useCallback,useEffect,useRef,useState} from "react";
import {apiFetch} from "@/lib/icheck-api";
import {Button} from "@/components/ui/button";
import {Input} from "@/components/ui/input";

type Definition={contract?:string;name:string;backend_id:string;enrollment_id:string;metric:string;measurement:"value"|"rate";
  rate_window_seconds:number;aggregation:"min"|"max"|"avg"|"sum";comparison:">"|">="|"<"|"<="|"=="|"!=";threshold:number;hold_seconds:number;
  severity:"info"|"warning"|"critical";enabled:boolean};
type Rule={id:string;name:string;enabled:boolean;revision:number;definition:Definition|null;applied_change_id:string|null};
type Change={id:string;rule_id:string;revision:number;definition:Definition;compiled_rule:{expr:string;for:string;labels:Record<string,string>;annotations:Record<string,string>};
  previous_definition:Definition|null;status:string;plan_hash:string;error_code:string|null;review_url:string;warning:string;test_evidence?:{current_value?:number;oldest_sample_timestamp?:number}};
type Target={enrollment_id:string;enrollment_revision:number;name:string;host:string;protocol:string;metrics:{name:string;type:string}[]};
type Principal={permissions:string[];authorization_scope:{all?:boolean};principal_type:string};
const control="mt-1 block w-full rounded border border-slate-300 bg-white p-2 text-sm";
const empty:Definition={name:"",backend_id:"",enrollment_id:"",metric:"",measurement:"value",rate_window_seconds:300,aggregation:"max",comparison:">",threshold:0,hold_seconds:60,severity:"warning",enabled:true};
function permits(actor:Principal|null,name:string){return Boolean(actor&&(actor.permissions.includes("*")||actor.permissions.includes(name)));}

export default function MetricRulesPage(){
  const [principal,setPrincipal]=useState<Principal|null>(null),[rules,setRules]=useState<Rule[]>([]),[targets,setTargets]=useState<Target[]>([]);
  const [setup,setSetup]=useState<{runtime_provisioned:boolean;backend_id:string|null;receiver:string;receiver_identity_configured:boolean}|null>(null);
  const [definition,setDefinition]=useState<Definition>(empty),[editing,setEditing]=useState<Rule|null>(null),[proposal,setProposal]=useState<Change|null>(null);
  const [history,setHistory]=useState<Change[]>([]),[approved,setApproved]=useState(false),[busy,setBusy]=useState(""),[error,setError]=useState("");
  const epoch=useRef(0),loadedProposal=useRef<string|null>(null); const target=targets.find(row=>row.enrollment_id===definition.enrollment_id);
  const withdrawing=!!editing&&!definition.enabled;
  const canConfirm=principal?.principal_type==="user"&&principal.authorization_scope.all===true&&permits(principal,"alerts.admin")&&permits(principal,"metrics.manage");
  const load=useCallback(async()=>{
    const request=++epoch.current;
    try{
      const actor=await apiFetch<Principal>("/auth/me");
      const [configuration,choices,installed,changes]=await Promise.all([
        apiFetch<NonNullable<typeof setup>>("/metric-alerts/setup"),apiFetch<{targets:Target[];has_more:boolean}>("/metric-alerts/targets"),
        apiFetch<Rule[]>("/metric-alerts/rules"),apiFetch<Change[]>("/metric-alerts/changes")]);
      if(request!==epoch.current)return;
      setPrincipal(actor);setSetup(configuration);setTargets(choices.targets);setRules(installed);setHistory(changes);
      setDefinition(current=>({...current,backend_id:current.backend_id||configuration.backend_id||""}));
      if(choices.has_more)setError("Showing the first 100 approved enrollments. Narrow the target selection in Assets.");
      const identifier=new URLSearchParams(window.location.search).get("proposal");
      if(identifier&&identifier!==loadedProposal.current&&/^[0-9a-f-]{36}$/.test(identifier)){
        const change=await apiFetch<Change>("/metric-alerts/changes/"+identifier);
        if(request===epoch.current){loadedProposal.current=identifier;setProposal(change);setApproved(false);}
      }
    }catch(cause){if(request===epoch.current){setPrincipal(null);setProposal(null);setError(cause instanceof Error?cause.message:"Metric rules could not be loaded");}}
  },[]);
  useEffect(()=>{const serial=epoch;const timer=window.setTimeout(()=>void load(),0);return()=>{window.clearTimeout(timer);serial.current++;};},[load]);
  async function run(label:string,operation:()=>Promise<void>){if(busy)return;setBusy(label);setError("");try{await operation();}catch(cause){setError(cause instanceof Error?cause.message:"Operation failed; inspect the retained state before retrying");}finally{setBusy("");}}
  function update<K extends keyof Definition>(key:K,value:Definition[K]){setDefinition(current=>({...current,[key]:value}));setProposal(null);setApproved(false);}
  async function preview(event:FormEvent){event.preventDefault();await run("preview",async()=>{
    const next=await apiFetch<Change>("/metric-alerts/preview",{method:"POST",body:JSON.stringify({definition,
      ...(editing?{rule_id:editing.id,expected_revision:editing.revision}:{})})});
    setProposal(next);setApproved(false);await load();
  });}
  async function confirm(){if(!proposal||!approved||!canConfirm)return;await run("confirm",async()=>{
    setProposal(await apiFetch<Change>(`/metric-alerts/changes/${proposal.id}/confirm`,{method:"POST",body:JSON.stringify({confirm:true,expected_plan_hash:proposal.plan_hash})}));
    setApproved(false);await load();
  });}
  async function inspect(){if(!proposal)return;await run("inspect",async()=>{
    setProposal(await apiFetch<Change>(`/metric-alerts/changes/${proposal.id}/confirm`,{method:"POST",body:JSON.stringify({confirm:true,expected_plan_hash:proposal.plan_hash})}));await load();
  });}
  function edit(rule:Rule){if(!rule.definition)return;setEditing(rule);setDefinition(rule.definition);setProposal(null);setApproved(false);window.history.replaceState(null,"","/alerts/metric-rules");}
  async function restore(change:Change){await run("restore",async()=>{setProposal(await apiFetch<Change>(`/metric-alerts/changes/${change.id}/restore-preview`,{method:"POST"}));setApproved(false);});}
  const metrics=target?.metrics||[];
  const aiBrief=`Prepare a Prometheus metric alert using an approved monitoring enrollment. List available targets and declared metrics, explain units and missing-data behavior, and return an exact preview for human review. Do not enable the rule.`;
  return <main className="min-h-screen bg-slate-50 p-4 sm:p-8"><div className="mx-auto max-w-5xl space-y-5">
    <nav className="flex flex-wrap gap-4 text-sm"><Link href="/">AI Operator</Link><Link href="/alerts">Alert evidence</Link><Link href="/alerts/alertmanager">Alertmanager</Link><Link href="/assets/devices">Assets</Link><Link href="/settings/observability">Prometheus settings</Link></nav>
    <header><h1 className="text-2xl font-semibold">Prometheus metric alerts</h1><p className="mt-2 text-sm">Describe a threshold to AI, or select an approved target here. Test actual samples, review the native rule, then explicitly enable it.</p>
      <Link className="mt-3 inline-block text-sm text-violet-700 underline" href={`/?brief=${encodeURIComponent(aiBrief)}`}>Ask AI to prepare a metric alert</Link></header>
    {error&&<p role="alert" className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</p>}
    <p className="rounded border bg-white p-3 text-sm">Prometheus is the only metric evaluator. Alertmanager delivers to {setup?.receiver||"the configured receiver"}; configuration alone does not verify delivery. Acknowledgement and condition clearance do not prove fault recovery.</p>
    {setup&&!setup.runtime_provisioned&&<p className="text-sm text-amber-800">The protected native rule runtime is not provisioned. No rule can be installed until the application and Alertmanager deployment are configured.</p>}
    <section className="rounded-xl border bg-white p-5"><h2 className="font-semibold">{editing?`Revise ${editing.name} · revision ${editing.revision}`:"Create a threshold rule"}</h2>
      <form onSubmit={event=>void preview(event)} className="mt-4 space-y-4"><fieldset disabled={!!busy||!setup?.runtime_provisioned} className="grid gap-4 sm:grid-cols-2">
        <label className="text-sm">Rule name<Input className="mt-1" required maxLength={128} readOnly={!!editing} value={definition.name} onChange={event=>update("name",event.target.value)}/></label>
        <label className="text-sm">Approved target<select aria-label="Approved target" className={control} required value={definition.enrollment_id} disabled={!!editing&&!definition.enabled} onChange={event=>{update("enrollment_id",event.target.value);update("metric","");}}>
          <option value="">Select an approved enrollment</option>{targets.map(row=><option key={row.enrollment_id} value={row.enrollment_id}>{row.name} · {row.protocol} · revision {row.enrollment_revision}</option>)}
          {editing&&!target&&<option value={definition.enrollment_id}>Saved source · currently unavailable</option>}</select></label>
        <label className="text-sm">Declared metric<select aria-label="Declared metric" className={control} required value={definition.metric} disabled={!!editing&&!definition.enabled} onChange={event=>{update("metric",event.target.value);update("measurement",metrics.find(metric=>metric.name===event.target.value)?.type==="counter"?"rate":"value");}}>
          <option value="">Select a declared measurement</option>{metrics.map(metric=><option key={metric.name} value={metric.name}>{metric.name} · {metric.type}</option>)}
          {editing&&!metrics.some(metric=>metric.name===definition.metric)&&<option value={definition.metric}>{definition.metric} · saved measurement</option>}</select></label>
        <label className="text-sm">Comparison<select aria-label="Comparison" disabled={withdrawing} className={control} value={definition.comparison} onChange={event=>update("comparison",event.target.value as Definition["comparison"])}>{[">",">=","<","<=","==","!="].map(value=><option key={value} value={value}>{value}</option>)}</select></label>
        <label className="text-sm">Threshold in the metric&apos;s reported units<Input disabled={withdrawing} required className="mt-1" type="number" step="any" value={definition.threshold} onChange={event=>update("threshold",Number(event.target.value))}/></label>
        <label className="text-sm">Must stay breached for (seconds)<Input disabled={withdrawing} required className="mt-1" type="number" min={0} max={3600} value={definition.hold_seconds} onChange={event=>update("hold_seconds",Number(event.target.value))}/></label>
        <label className="text-sm">Severity<select aria-label="Severity" disabled={withdrawing} className={control} value={definition.severity} onChange={event=>update("severity",event.target.value as Definition["severity"])}>{["info","warning","critical"].map(value=><option key={value} value={value}>{value}</option>)}</select></label>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={!editing} checked={definition.enabled} onChange={event=>update("enabled",event.target.checked)}/>Enable after confirmation (uncheck an existing rule to withdraw)</label>
      </fieldset>
      {withdrawing&&<p className="text-sm">Withdrawal retains the saved definition and does not require source samples. Re-enable editing before changing its threshold.</p>}
      <p className="text-xs">Use the metric&apos;s reported units, not an inferred percentage. Save its target-specific dashboard in Studio first. Missing samples do not prove recovery.</p>
      <details><summary className="cursor-pointer text-xs">Advanced measurement and enrollment details</summary><fieldset disabled={!!busy||withdrawing||!setup?.runtime_provisioned} className="mt-3 grid gap-3 sm:grid-cols-2">
        <label className="text-sm">Aggregation<select aria-label="Aggregation" className={control} value={definition.aggregation} onChange={event=>update("aggregation",event.target.value as Definition["aggregation"])}>{["min","max","avg","sum"].map(value=><option key={value} value={value}>{value}</option>)}</select></label>
        <label className="text-sm">Counter rate window (seconds)<Input className="mt-1" type="number" min={60} max={3600} value={definition.rate_window_seconds} onChange={event=>update("rate_window_seconds",Number(event.target.value))}/></label>
      </fieldset><p className="mt-2 break-all text-xs">Measurement: {definition.measurement}. Backend: {definition.backend_id||"not configured"}. Enrollment: {definition.enrollment_id||"not selected"}. No arbitrary PromQL, paths or notification secrets are accepted.</p></details>
      <Button disabled={!!busy||!setup?.runtime_provisioned}>Test samples and preview rule</Button>{editing&&<Button type="button" variant="outline" className="ml-3" disabled={!!busy} onClick={()=>{setEditing(null);setDefinition({...empty,backend_id:setup?.backend_id||""});setProposal(null);setApproved(false);}}>New rule</Button>}
      </form></section>
    {proposal&&<section className="space-y-3 rounded-xl border border-violet-200 bg-white p-5" aria-label="Metric rule preview"><h2 className="font-semibold">{proposal.definition.name} · {proposal.status}</h2>
      <p className="text-sm">{proposal.definition.metric} {proposal.definition.comparison} {proposal.definition.threshold} for {proposal.definition.hold_seconds}s · revision {proposal.revision} · {proposal.definition.enabled?"enable":"withdraw"}</p>
      {proposal.test_evidence?.current_value!==undefined&&<p className="text-sm">Actual test value: {proposal.test_evidence.current_value}. This is a measurement check, not proof of notification delivery.</p>}
      {proposal.compiled_rule.annotations.dashboard_url?.startsWith("https://")&&<a className="inline-block text-sm text-violet-700 underline" href={proposal.compiled_rule.annotations.dashboard_url}>Open saved target dashboard in Grafana</a>}
      <details><summary className="cursor-pointer text-xs">Native Prometheus definition and retained prior version</summary><pre className="mt-3 overflow-x-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify({rule:proposal.compiled_rule,previous:proposal.previous_definition},null,2)}</pre></details>
      {proposal.status==="proposed"&&<><label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={approved} onChange={event=>setApproved(event.target.checked)}/>Apply this exact reviewed rule to the displayed target. Alertmanager delivery remains a separate observed result.</label><Button disabled={!approved||!canConfirm||!!busy} onClick={()=>void confirm()}>Confirm reviewed rule</Button></>}
      {["applying","unknown"].includes(proposal.status)&&<><p className="text-sm text-amber-800">Write outcome is uncertain. Inspect this retained change; do not submit a replacement write.</p><Button variant="outline" disabled={!canConfirm||!!busy} onClick={()=>void inspect()}>Inspect previous write</Button></>}
      {proposal.status==="applied"&&<p role="status" className="text-sm">Native rule reload verified. Open <Link className="underline" href="/alerts">Alert evidence</Link> to inspect actual delivery; applied does not mean a fault fired or recovered.</p>}
      <p className="text-xs text-muted-foreground">{proposal.warning}</p></section>}
    <section className="rounded-xl border bg-white p-5"><h2 className="font-semibold">Retained metric rules</h2><ul className="mt-3 space-y-3">{rules.map(rule=><li key={rule.id} className="flex flex-wrap items-center justify-between gap-3 rounded border p-3 text-sm"><span>{rule.name} · revision {rule.revision} · {rule.enabled?"applied definition enabled":"not enabled"}</span><Button variant="outline" disabled={!!busy||!rule.definition} onClick={()=>edit(rule)}>Edit / withdraw</Button></li>)}</ul></section>
    <details className="rounded border bg-white p-4"><summary className="cursor-pointer text-sm">Version history and rollback</summary><ul className="mt-3 space-y-3">{history.map(change=><li key={change.id} className="flex flex-wrap items-center justify-between gap-3 text-sm"><span>{change.definition.name} · revision {change.revision} · {change.status}</span>{change.status==="applied"&&change.previous_definition&&<Button variant="outline" disabled={!!busy} onClick={()=>void restore(change)}>Preview prior definition</Button>}</li>)}</ul></details>
  </div></main>;
}
