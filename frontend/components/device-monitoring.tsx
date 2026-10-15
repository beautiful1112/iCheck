"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { APIError, BrowserContextChangedError, apiFetch } from "@/lib/icheck-api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {defaultMonitoringProfile, exporterCollectors, type ExporterMonitorSpec, type MonitoringProtocol} from "@/lib/exporter-monitor";

type Enrollment = {
  id: string;
  revision: number;
  enabled: boolean;
  gateway_profile: string;
  modules: string[];
  collectors: string[];
  schedule_seconds: number;
  timeout_seconds: number;
  approved_until: string;
  approved_by: string;
};

type Preview = {
  preview_hash: string;
  eligible: boolean;
  blockers: string[];
  warnings: string[];
  currently_authorized: boolean;
  enrollment: Enrollment | null;
};

const fieldClass = "h-8 border-[#c9cdd4] bg-white text-xs";

type MonitoringProps = {
  deviceId: string; connectionId: string; protocol: MonitoringProtocol;
  configuration?: {modules?: string[]; exporter_monitor?: ExporterMonitorSpec; monitoring_template_version_id?: string};
};

export function DeviceMonitoring(props: MonitoringProps) {
  return <MonitoringPanel key={`${props.deviceId}:${props.connectionId}:${props.protocol}`} {...props} />;
}

function MonitoringPanel({ deviceId, connectionId, protocol, configuration }: MonitoringProps) {
  const path = `/assets/devices/${encodeURIComponent(deviceId)}/connections/${encodeURIComponent(connectionId)}/monitoring`;
  const serial = useRef(0);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [canWrite, setCanWrite] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const exporter = configuration?.exporter_monitor;
  const templateNames = protocol === "snmp" ? configuration?.modules?.join(",") || "if_mib" :
    exporter ? exporterCollectors(exporter).join(",") : protocol === "windows_exporter" ? "cpu,memory" : "";
  const templateBound = Boolean(exporter || configuration?.monitoring_template_version_id);
  const [gateway, setGateway] = useState<string>(defaultMonitoringProfile(protocol));
  const [names, setNames] = useState(templateNames);
  const [schedule, setSchedule] = useState("30");
  const [timeout, setTimeout] = useState("10");
  const [validity, setValidity] = useState("168");
  const [reason, setReason] = useState("Continuously monitor this verified connection.");

  useEffect(() => {
    const request = ++serial.current;
    Promise.all([
      apiFetch<Preview>(path),
      apiFetch<{ permissions: string[] }>("/auth/me"),
    ]).then(([current, principal]) => {
      if (serial.current !== request) return;
      setPreview(current);
      setCanWrite(principal.permissions.includes("*") || principal.permissions.includes("assets.write"));
      if (current.enrollment) {
        setGateway(current.enrollment.gateway_profile);
        setNames(templateBound ? templateNames :
          (protocol === "snmp" ? current.enrollment.modules : current.enrollment.collectors).join(","));
        setSchedule(String(current.enrollment.schedule_seconds));
        setTimeout(String(current.enrollment.timeout_seconds));
      } else setNames(templateNames);
    }).catch((error) => {
      if (serial.current === request) setMessage(error instanceof Error ? error.message : "Monitoring intent could not be loaded.");
    });
    return () => { serial.current += 1; };
  }, [path, protocol, templateNames, templateBound]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!preview || !canWrite || busy) return;
    const request = ++serial.current;
    setBusy(true);
    setMessage(null);
    try {
      const selectedNames = (templateBound ? templateNames : names).split(",").map((name) => name.trim()).filter(Boolean);
      await apiFetch<Enrollment>(path + "/approve", {
        method: "POST",
        body: JSON.stringify({
          expected_revision: preview.enrollment?.revision ?? 0,
          preview_hash: preview.preview_hash,
          gateway_profile: gateway.trim(),
          modules: protocol === "snmp" ? selectedNames : [],
          collectors: protocol === "windows_exporter" || protocol === "node_exporter" || protocol === "cadvisor" || protocol === "vmware_exporter" ? selectedNames : [],
          schedule_seconds: Number(schedule), timeout_seconds: Number(timeout),
          validity_hours: Number(validity), actor: "web.operator", reason,
        }),
      });
      const current = await apiFetch<Preview>(path);
      if (serial.current === request) {
        setPreview(current);
        setMessage("Collection approved. Check fresh measurements in Studio and Grafana before treating monitoring as healthy.");
      }
    } catch (error) {
      if (serial.current === request) {
        setMessage(error instanceof Error ? error.message : "Monitoring approval failed.");
        if (error instanceof BrowserContextChangedError || (error instanceof APIError && [401, 403].includes(error.status))) {
          setPreview(null);
          setCanWrite(false);
          return;
        }
        try {
          const current = await apiFetch<Preview>(path);
          if (serial.current === request) setPreview(current);
        } catch {
          if (serial.current === request) setPreview(null);
        }
      }
    } finally {
      if (serial.current === request) setBusy(false);
    }
  }

  async function withdraw() {
    if (!preview?.enrollment || !canWrite || busy) return;
    const request = ++serial.current;
    setBusy(true);
    setMessage(null);
    try {
      await apiFetch<Enrollment>(path + "/withdraw", {
        method: "POST", body: JSON.stringify({ expected_revision: preview.enrollment.revision,
          actor: "web.operator", reason }),
      });
      const current = await apiFetch<Preview>(path);
      if (serial.current === request) {
        setPreview(current);
        setMessage("Monitoring withdrawn. The gateway refuses future scrapes, including cached discovery targets.");
      }
    } catch (error) {
      if (serial.current === request) {
        setMessage(error instanceof Error ? error.message : "Monitoring withdrawal failed.");
        if (error instanceof BrowserContextChangedError || (error instanceof APIError && [401, 403].includes(error.status))) {
          setPreview(null);
          setCanWrite(false);
        }
      }
    } finally {
      if (serial.current === request) setBusy(false);
    }
  }

  return (
    <section className="mt-3 border-t border-[#eceef0] pt-3" aria-label={`${protocol.replaceAll("_", " ")} continuous monitoring`}>
      <h3 className="text-xs font-semibold text-[#4f5d73]">Continuous Prometheus collection</h3>
      <p className="mt-1 text-[11px] text-muted-foreground">
        {preview ? (preview.currently_authorized ? "Authorized intent; live scrape health is not proven here." : "Not currently authorized for continuous scraping.") : "Loading current monitoring authority…"}
      </p>
      {preview?.enrollment ? <p className="mt-1 text-[11px] text-muted-foreground">
        Revision {preview.enrollment.revision}; expires {new Date(preview.enrollment.approved_until).toLocaleString()}; approved by {preview.enrollment.approved_by}.
      </p> : null}
      {preview?.blockers.map((blocker) => <p key={blocker} className="mt-1 text-[11px] text-[#a52a2a]">{blocker}</p>)}
      {preview?.warnings.map((warning) => <p key={warning} className="mt-1 text-[11px] text-muted-foreground">{warning}</p>)}
      {canWrite && preview ? <form onSubmit={save} className="mt-3 space-y-2">
        <fieldset disabled={busy} className="space-y-2">
          {exporter ? <p className="text-[11px] text-[#4f5d73]">Measurements from the tested template: {exporter.groups.map(group => group === "cpu" ? "CPU" : group).join(", ")}.
            {exporter.plugin === "vmware" ? ` Object: ${exporter.vmware_name}.` : ""}
            {exporter.plugin === "containers" ? (exporter.container_name || exporter.container_id ? ` Container: ${exporter.container_name || exporter.container_id}.` : " Container scope: all matching runtime containers.") : ""}
            {" "}Edit the template in Capability Studio and retest to change its measurements.</p> : null}
          <div className="max-w-48">
            <label className="text-[11px] text-[#4f5d73]">Interval (s)
              <Input required type="number" min={15} max={3600} value={schedule} onChange={(event) => setSchedule(event.target.value)} className={fieldClass} />
            </label>
          </div>
          <p className="text-[10px] text-muted-foreground">New approval lasts {validity} hours. It permits collection, not infrastructure changes or remediation.</p>
          <details className="space-y-2"><summary className="cursor-pointer text-[11px]">Advanced details</summary>
            <label className="block text-[11px] text-[#4f5d73]">Protected gateway profile
              <Input required pattern={"[A-Za-z0-9_.\\-]{1,63}"} value={gateway} onChange={(event) => setGateway(event.target.value)} className={fieldClass} />
            </label>
            <p className="text-[10px] text-muted-foreground">The native preview profile is selected automatically. Use another provisioned profile only when needed; never enter a secret here.</p>
            {protocol !== "https_api" && <label className="block text-[11px] text-[#4f5d73]">{protocol === "snmp" ? "SNMP modules" : "Exporter collectors or scopes"}
              <Input required={protocol === "snmp"} readOnly={templateBound} value={templateBound ? templateNames : names} onChange={(event) => setNames(event.target.value)} className={fieldClass} />
            </label>}
            <div className="grid grid-cols-2 gap-2">
              <label className="text-[11px] text-[#4f5d73]">Timeout (s)
                <Input required type="number" min={1} max={30} value={timeout} onChange={(event) => setTimeout(event.target.value)} className={fieldClass} />
              </label>
              <label className="text-[11px] text-[#4f5d73]">Approval (h)
                <Input required type="number" min={1} max={720} value={validity} onChange={(event) => setValidity(event.target.value)} className={fieldClass} />
              </label>
            </div>
            <label className="block text-[11px] text-[#4f5d73]">Approval or withdrawal reason
              <Input required minLength={10} maxLength={1000} value={reason} onChange={(event) => setReason(event.target.value)} className={fieldClass} />
            </label>
          </details>
          <div className="flex flex-wrap gap-2">
            <Button type="submit" size="sm" disabled={!preview.eligible || busy} className="h-7 text-[11px]">
              {preview.enrollment ? "Update / renew approval" : "Approve continuous collection"}
            </Button>
            {preview.enrollment?.enabled ? <Button type="button" size="sm" variant="outline" disabled={busy || reason.trim().length < 10} onClick={() => void withdraw()} className="h-7 text-[11px]">Withdraw</Button> : null}
          </div>
        </fieldset>
      </form> : null}
      {message ? <p role="status" className="mt-2 text-xs text-[#4f5d73]">{message}</p> : null}
    </section>
  );
}
