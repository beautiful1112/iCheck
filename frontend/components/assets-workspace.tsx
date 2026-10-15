"use client";

import Link from "next/link";
import {
  FormEvent,
  Fragment,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import {
  Activity,
  ArrowLeft,
  CheckCircle2,
  KeyRound,
  MonitorCog,
  Network,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldCheck,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { DeviceMonitoring } from "@/components/device-monitoring";
import { DeviceNativeSSH } from "@/components/device-native-ssh";
import { DeviceSSHAccess } from "@/components/device-ssh-access";
import { SNMPConfiguration } from "@/components/snmp-configuration";
import { HTTPConfiguration } from "@/components/http-configuration";
import type { HTTPMonitorSpec } from "@/lib/http-monitor";
import type { ExporterMonitorSpec } from "@/lib/exporter-monitor";
import { DeviceLiveStatus, healthTone } from "@/components/device-live-status";
import { DeviceDashboards } from "@/components/device-dashboards";
import { assetCategories, healthLabel, inventoryPagePath, type DeviceHealth } from "@/lib/asset-inventory";
import { DeviceLocationFields } from "@/components/device-location-fields";
import { networkDashboardHref } from "@/lib/grafana-links";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { APIError, apiFetch as apiRequest } from "@/lib/icheck-api";
import { credentialReferenceEligible, eligibleCredentialProfiles, formatDeviceLocation, deviceDisplayName,
  verificationMethodAvailable, type DeviceLocation, type OnboardingWorker } from "@/lib/device-onboarding";
import { cn } from "@/lib/utils";

type Protocol =
  | "snmp"
  | "https_api"
  | "ssh"
  | "node_exporter"
  | "cadvisor"
  | "vmware_exporter"
  | "windows_exporter"
  | "winrm_https"
  | "icmp";

type DevicePage = {
  items: Device[];
  next_cursor: string | null;
};

type VerificationRecord = {id: string; status: string; started_at: string; finished_at: string | null;
  error: string | null; evidence: {verification_level?: string; authentication_tested?: boolean}};

type CredentialProfile = {
  id: string;
  name: string;
  provider: string;
  secret_ref: string;
  allowed_adapters: string[];
  worker_selector: Record<string, string>;
  enabled: boolean;
};

type ConnectionActivation = {
  id: string;
  capability_key: string;
  policy_id: string;
  deployment_id: string | null;
  status: string;
  plan_hash: string;
  expected_deployment_hash: string;
  runtime_status: string;
  consecutive_failures: number;
  last_run_id: string | null;
  last_run_status: string | null;
  last_run_finished_at: string | null;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_evaluated_at: string | null;
  health_reason: string | null;
  approved_by: string;
  approval_reason: string;
  activated_at: string;
  deactivated_at: string | null;
  deactivated_by: string | null;
  deactivation_reason: string | null;
  last_error: string | null;
};

type DeviceConnection = {
  id: string;
  protocol: Protocol;
  adapter_type: string;
  port: number | null;
  credential_profile_ref: string | null;
  worker_selector: Record<string, string>;
  configuration: { modules?: string[]; http_monitor?: HTTPMonitorSpec; exporter_monitor?: ExporterMonitorSpec; monitoring_template_version_id?: string; verification_mode?: "studio" };
  enabled: boolean;
  verification_status: string;
  last_verified_at: string | null;
  last_verification_error: string | null;
  last_verification_worker_id: string | null;
  last_verification_latency_ms: number | null;
  last_verification_evidence: Record<string, unknown>;
  verification_lease_expires_at: string | null;
  activations: ConnectionActivation[];
  activation: ConnectionActivation | null;
};

type Device = {
  id: string;
  name: string;
  discovered_name?: string | null;
  kind: string;
  management_ip: string | null;
  vendor: string | null;
  model: string | null;
  site: string | null;
  location?: DeviceLocation;
  labels: Record<string, string>;
  onboarding_status: string;
  enabled: boolean;
  revision: number;
  identity_revision: number;
  connections: DeviceConnection[];
};

type DeviceMetadataDraft = {
  kind: string;
  vendor: string | null;
  model: string | null;
  labels: Record<string, string>;
  location: DeviceLocation;
};

type IdentityCorrectionPreview = {
  device_id: string;
  expected_revision: number;
  current: Record<string, string | null>;
  proposed: Record<string, string>;
  connections: Array<{
    connection_id: string;
    protocol: string;
    current_credential_profile_ref: string | null;
    proposed_credential_profile_ref: string | null;
    proposed_worker_selector: Record<string, string>;
  }>;
  blockers: string[];
  warnings: string[];
  preview_hash: string;
  can_commit: boolean;
};

type ActivationPolicy = {
  id: string;
  name: string;
  version: number;
  status: string;
  protocol: Protocol;
  adapter_type: string;
  execution_mode: "scheduled" | "on_demand";
  schedule_seconds: number;
};

type ActivationPlan = {
  policy_id: string;
  policy_name: string;
  policy_version: number;
  connection_id: string;
  scope_device_identity_revision: number;
  target_classification: "registered_device";
  deployment_name: string;
  artifact_version_id: string;
  artifact_name: string;
  artifact_version: number;
  target: Record<string, unknown>;
  configuration: Record<string, unknown>;
  worker_selector: Record<string, string>;
  execution_mode: "scheduled" | "on_demand";
  schedule_seconds: number;
  credential_profile_ref: string | null;
  warnings: string[];
  plan_hash: string;
};

const protocolOptions: Array<{
  value: Protocol;
  label: string;
  adapter: string;
  port: string;
  description: string;
}> = [
  {
    value: "snmp",
    label: "SNMP",
    adapter: "snmp_exporter",
    port: "161",
    description: "Network inventory and interface metrics",
  },
  {
    value: "https_api",
    label: "HTTPS API",
    adapter: "http_json",
    port: "443",
    description: "Vendor controller or appliance API",
  },
  {
    value: "ssh",
    label: "SSH",
    adapter: "ssh",
    port: "22",
    description: "Read-only CLI diagnostics",
  },
  {
    value: "windows_exporter",
    label: "Windows exporter",
    adapter: "windows_exporter",
    port: "9182",
    description: "Continuous Windows metrics",
  },
  {
    value: "node_exporter",
    label: "Linux exporter",
    adapter: "node_exporter",
    port: "9100",
    description: "Linux metrics; select and test a template in Capability Studio",
  },
  {
    value: "cadvisor",
    label: "Container exporter (cAdvisor)",
    adapter: "cadvisor",
    port: "8080",
    description: "Container metrics; requires an existing cAdvisor endpoint and tested Studio template",
  },
  {
    value: "vmware_exporter",
    label: "VMware exporter (source preview)",
    adapter: "vmware_exporter",
    port: "9272",
    description: "Existing exporter endpoint; select and test a VMware object in Studio",
  },
  {
    value: "winrm_https",
    label: "WinRM HTTPS",
    adapter: "psrp_cim",
    port: "5986",
    description: "Governed on-demand CIM diagnostics",
  },
  {
    value: "icmp",
    label: "ICMP",
    adapter: "icmp",
    port: "",
    description: "Basic reachability intent",
  },
];

const activationAdapters: Record<Protocol, readonly string[]> = {
  snmp: ["snmp_exporter", "snmp_topology"],
  https_api: ["http_json", "http_json_sandbox"],
  ssh: ["ssh", "ssh_command_sandbox"],
  windows_exporter: ["windows_exporter"],
  node_exporter: ["node_exporter"],
  cadvisor: ["cadvisor"],
  vmware_exporter: ["vmware_exporter"],
  winrm_https: ["psrp_cim"],
  icmp: ["icmp"],
};

const deviceKinds = [
  ["firewall", "Firewall"],
  ["switch", "Switch"],
  ["router", "Router"],
  ["linux_server", "Linux server"],
  ["windows_server", "Windows server"],
  ["wireless_controller", "Wireless controller"],
  ["wireless_access_point", "Wireless access point"],
  ["physical_server", "Physical server"],
  ["load_balancer", "Load balancer"],
  ["storage", "Storage"],
  ["hypervisor", "Hypervisor"],
  ["other", "Other"],
];

const inputClass =
  "h-10 border-[#b1b7c1] bg-white text-sm shadow-none focus-visible:border-[#5856d6] focus-visible:ring-[#5856d6]/15";
const selectClass =
  "h-10 w-full rounded-md border border-[#b1b7c1] bg-white px-3 text-sm text-[#2c384a] outline-none focus:border-[#5856d6] focus:ring-2 focus:ring-[#5856d6]/15";

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="mb-1.5 block text-xs font-semibold text-[#4f5d73]">
      {children}
    </span>
  );
}

function parseLabels(value: string): Record<string, string> {
  return Object.fromEntries(
    value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
      .map((item) => {
        const [key, ...rest] = item.split("=");
        return [key.trim(), rest.join("=").trim()];
      })
      .filter(([key, item]) => key && item),
  );
}

function parseEditableLabels(value: string): Record<string, string> {
  const parsed: unknown = JSON.parse(value);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("Labels must be a JSON object of string values.");
  }
  const labels = parsed as Record<string, unknown>;
  if (Object.values(labels).some((item) => typeof item !== "string")) {
    throw new Error("Every label value must be a string.");
  }
  return labels as Record<string, string>;
}

function statusClass(status: string) {
  if (["verified", "active", "monitoring_configured"].includes(status)) {
    return "border-[#2eb85c]/30 bg-[#2eb85c]/10 text-[#166534]";
  }
  if (
    status.includes("failed") ||
    ["degraded", "drifted", "stale"].includes(status)
  ) {
    return "border-[#e55353]/30 bg-[#e55353]/10 text-[#a52a2a]";
  }
  if (status === "running" || status === "verifying") {
    return "border-[#5856d6]/30 bg-[#5856d6]/10 text-[#4947ad]";
  }
  return "border-[#f9b115]/30 bg-[#f9b115]/10 text-[#8b6300]";
}

function DeviceMetadataEditor({
  device,
  saving,
  onSave,
}: {
  device: Device;
  saving: boolean;
  onSave: (draft: DeviceMetadataDraft) => Promise<void>;
}) {
  const [kind, setKind] = useState(device.kind);
  const [vendor, setVendor] = useState(device.vendor || "");
  const [model, setModel] = useState(device.model || "");
  const [labels, setLabels] = useState(JSON.stringify(device.labels, null, 2));
  const [location, setLocation] = useState<DeviceLocation>(device.location || {});
  const [validationError, setValidationError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const parsedLabels = parseEditableLabels(labels);
      setValidationError(null);
      await onSave({
        kind,
        vendor: vendor.trim() || null,
        model: model.trim() || null,
        labels: parsedLabels,
        location,
      });
    } catch (error) {
      setValidationError(error instanceof Error ? error.message : "Invalid metadata");
    }
  }

  return (
    <form onSubmit={(event) => void submit(event)} className="mb-4 rounded-md border border-[#d8dbe0] bg-white p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="text-sm font-semibold text-[#2c384a]">Device metadata</p>
          <p className="mt-1 text-xs text-muted-foreground">Edit descriptive fields here. Use the reviewed identity-correction form below for name, IP, site, or credential changes.</p>
        </div>
        <span className="text-[11px] text-muted-foreground">Revision {device.revision}</span>
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <label><FieldLabel>Type</FieldLabel><select value={kind} onChange={(event) => setKind(event.target.value)} className={selectClass}>{deviceKinds.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
        <label><FieldLabel>Vendor</FieldLabel><Input value={vendor} onChange={(event) => setVendor(event.target.value)} maxLength={128} className={inputClass} /></label>
        <label><FieldLabel>Model</FieldLabel><Input value={model} onChange={(event) => setModel(event.target.value)} maxLength={128} className={inputClass} /></label>
        <label><FieldLabel>Labels (JSON)</FieldLabel><textarea value={labels} onChange={(event) => setLabels(event.target.value)} rows={3} spellCheck={false} className={cn(selectClass, "h-auto min-h-20 py-2 font-mono text-xs")} /></label>
      </div>
      <DeviceLocationFields value={location} onChange={setLocation} />
      {validationError ? <p role="alert" className="mt-2 text-xs text-[#a52a2a]">{validationError}</p> : null}
      <Button type="submit" size="sm" disabled={saving} className="mt-3 bg-[#5856d6] text-white hover:bg-[#4947ad]">
        {saving ? <RefreshCw className="size-3 animate-spin" /> : null} Save metadata
      </Button>
    </form>
  );
}

function DeviceIdentityEditor({
  device,
  credentials,
  onCommitted,
  onConflict,
}: {
  device: Device;
  credentials: CredentialProfile[];
  onCommitted: (updated: Device) => void;
  onConflict: () => Promise<void>;
}) {
  const [name, setName] = useState(device.name);
  const [managementIp, setManagementIp] = useState(device.management_ip || "");
  const [site, setSite] = useState(device.site || "");
  const [credentialRefs, setCredentialRefs] = useState<Record<string, string>>(
    Object.fromEntries(device.connections.map((item) => [
      item.id, item.credential_profile_ref || "",
    ])),
  );
  const [reason, setReason] = useState("");
  const [preview, setPreview] = useState<IdentityCorrectionPreview | null>(null);
  const [busy, setBusy] = useState<"preview" | "commit" | null>(null);
  const [error, setError] = useState<string | null>(null);

  function invalidate() {
    setPreview(null);
    setError(null);
  }

  function correctionInput() {
    return {
      expected_revision: device.revision,
      name: name.trim(),
      management_ip: managementIp.trim(),
      site: site.trim(),
      credential_profile_refs: Object.fromEntries(
        device.connections.map((item) => [item.id, credentialRefs[item.id] || null]),
      ),
    };
  }

  async function handleConflict() {
    try {
      await onConflict();
    } catch {
      setError("Device changed while this editor was open. Refresh the page before retrying.");
    }
  }

  async function requestPreview() {
    setBusy("preview");
    setError(null);
    try {
      const result = await apiRequest<IdentityCorrectionPreview>(
        `/assets/devices/${device.id}/identity-correction/preview`,
        { method: "POST", body: JSON.stringify(correctionInput()) },
      );
      setPreview(result);
    } catch (caught) {
      setPreview(null);
      if (caught instanceof APIError && caught.status === 409) {
        await handleConflict();
      } else {
        setError(caught instanceof Error ? caught.message : "Unable to preview correction");
      }
    } finally {
      setBusy(null);
    }
  }

  async function commit() {
    if (!preview?.can_commit || !reason.trim()) return;
    setBusy("commit");
    setError(null);
    try {
      const updated = await apiRequest<Device>(
        `/assets/devices/${device.id}/identity-correction/commit`,
        {
          method: "POST",
          body: JSON.stringify({
            ...correctionInput(),
            preview_hash: preview.preview_hash,
            actor: "assets.operator",
            reason: reason.trim(),
          }),
        },
      );
      onCommitted(updated);
    } catch (caught) {
      setPreview(null);
      if (caught instanceof APIError && caught.status === 409) {
        await handleConflict();
      } else {
        setError(caught instanceof Error ? caught.message : "Unable to commit correction");
      }
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="mb-4 rounded-md border border-[#d8dbe0] bg-white p-4">
      <p className="text-sm font-semibold text-[#2c384a]">Correct device identity</p>
      <p className="mt-1 text-xs text-muted-foreground">
        Preview blockers before changing name, management IP, site, or credential bindings. A committed correction clears current verification and requires fresh policy approval; it never retargets an old deployment.
      </p>
      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <label><FieldLabel>Name</FieldLabel><Input value={name} onChange={(event) => { setName(event.target.value); invalidate(); }} maxLength={255} className={inputClass} /></label>
        <label><FieldLabel>Management IP</FieldLabel><Input value={managementIp} onChange={(event) => { setManagementIp(event.target.value); invalidate(); }} className={cn(inputClass, "font-mono")} /></label>
        <label><FieldLabel>Site</FieldLabel><Input value={site} onChange={(event) => { setSite(event.target.value); invalidate(); }} maxLength={128} className={inputClass} /></label>
      </div>
      {device.connections.map((connection) => {
        const currentRef = credentialRefs[connection.id] || "";
        const eligible = credentials.filter((profile) =>
          profile.allowed_adapters.includes(connection.adapter_type) &&
          Object.entries(profile.worker_selector).every(([key, value]) =>
            (!site.trim() || ({ ...connection.worker_selector, site: site.trim() })[key] === value),
          ),
        );
        return (
          <label key={connection.id} className="mt-3 block max-w-lg">
            <FieldLabel>{connection.protocol.replaceAll("_", " ")} credential reference</FieldLabel>
            <select
              value={currentRef}
              onChange={(event) => {
                setCredentialRefs((current) => ({ ...current, [connection.id]: event.target.value }));
                invalidate();
              }}
              className={selectClass}
            >
              <option value="">No credential profile</option>
              {currentRef && !eligible.some((profile) =>
                profile.id === currentRef || profile.name === currentRef
              ) ? <option value={currentRef}>Current reference (not eligible at this site)</option> : null}
              {eligible.map((profile) => (
                <option key={profile.id} value={profile.id === currentRef ? profile.id : profile.name}>{profile.name}</option>
              ))}
            </select>
          </label>
        );
      })}
      <Button type="button" size="sm" variant="outline" disabled={busy !== null} onClick={() => void requestPreview()} className="mt-3 border-[#c9cdd4]">
        {busy === "preview" ? <RefreshCw className="size-3 animate-spin" /> : null} Preview correction
      </Button>
      {preview ? (
        <div className="mt-3 rounded-md border border-[#d8dbe0] bg-[#f8f9fa] p-3 text-xs text-[#4f5d73]">
          <p className="font-semibold">Revision {preview.expected_revision} · {preview.can_commit ? "Ready for reviewed commit" : "Blocked"}</p>
          <p className="mt-1 font-mono">{preview.current.management_ip || "—"} → {preview.proposed.management_ip}</p>
          {preview.blockers.length ? <ul className="mt-2 list-disc space-y-1 pl-4 text-[#a52a2a]">{preview.blockers.map((item) => <li key={item}>{item}</li>)}</ul> : null}
          {preview.warnings.length ? <ul className="mt-2 list-disc space-y-1 pl-4">{preview.warnings.map((item) => <li key={item}>{item}</li>)}</ul> : null}
          {preview.can_commit ? (
            <div className="mt-3 max-w-xl">
              <label><FieldLabel>Reason for correction</FieldLabel><Input value={reason} onChange={(event) => setReason(event.target.value)} maxLength={2000} placeholder="Why is this the same physical device at a new target?" className={inputClass} /></label>
              <Button type="button" size="sm" disabled={busy !== null || !reason.trim()} onClick={() => void commit()} className="mt-2 bg-[#5856d6] text-white hover:bg-[#4947ad]">
                {busy === "commit" ? <RefreshCw className="size-3 animate-spin" /> : null} Commit and reverify
              </Button>
            </div>
          ) : null}
        </div>
      ) : null}
      {error ? <p role="alert" className="mt-2 text-xs text-[#a52a2a]">{error}</p> : null}
    </div>
  );
}

export default function AssetsWorkspace({ mode = "inventory" }: { mode?: "inventory" | "add" }) {
  const [category, setCategory] = useState("");
  const [summary, setSummary] = useState<{total: number; categories: Record<string, number>} | null>(null);
  const [health, setHealth] = useState<Record<string, DeviceHealth>>({});
  const [detailTab, setDetailTab] = useState<"status" | "templates" | "settings">("status");
  const [healthRefresh, setHealthRefresh] = useState(0);
  const [canWrite, setCanWrite] = useState(false);
  const [canActivate, setCanActivate] = useState(false);
  const [canManageSSH, setCanManageSSH] = useState(false);
  const [devices, setDevices] = useState<Device[]>([]);
  const [credentials, setCredentials] = useState<CredentialProfile[]>([]);
  const [activationPolicies, setActivationPolicies] = useState<ActivationPolicy[]>([]);
  const [selectedPolicies, setSelectedPolicies] = useState<Record<string, string>>({});
  const [activationPlans, setActivationPlans] = useState<Record<string, ActivationPlan>>({});
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [currentCursor, setCurrentCursor] = useState<string | undefined>(undefined);
  const [previousCursors, setPreviousCursors] = useState<string[]>([]);
  const requestSerial = useRef(0);
  const [saving, setSaving] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [expandedDeviceId, setExpandedDeviceId] = useState<string | null>(null);
  const [focusedDeviceId, setFocusedDeviceId] = useState<string | null>(null);
  const [message, setMessage] = useState<{
    tone: "success" | "error";
    text: string;
  } | null>(null);

  const [name, setName] = useState("");
  const [managementIp, setManagementIp] = useState("");
  const [kind, setKind] = useState("switch");
  const [site, setSite] = useState("");
  const [location, setLocation] = useState<DeviceLocation>({});
  const [requestMonitoring, setRequestMonitoring] = useState(true);
  const [nativeSSH, setNativeSSH] = useState(true);
  const [vendor, setVendor] = useState("");
  const [model, setModel] = useState("");
  const [labels, setLabels] = useState("environment=lab");
  const [selectedProtocols, setSelectedProtocols] = useState<Protocol[]>([
    "snmp",
  ]);
  const [verificationWorkers, setVerificationWorkers] = useState<OnboardingWorker[] | null>(null);
  const [verificationHistory, setVerificationHistory] = useState<Record<string, VerificationRecord[]>>({});
  const [ports, setPorts] = useState<Record<Protocol, string>>(
    Object.fromEntries(
      protocolOptions.map((protocol) => [protocol.value, protocol.port]),
    ) as Record<Protocol, string>,
  );
  const [connectionCredentials, setConnectionCredentials] = useState<
    Partial<Record<Protocol, string>>
  >({});

  const [credentialName, setCredentialName] = useState("");
  const [credentialProvider, setCredentialProvider] = useState("vault");
  const [secretRef, setSecretRef] = useState("kv/lab/network-readonly");
  const [credentialSite, setCredentialSite] = useState("LAB");
  const [allowedAdapters, setAllowedAdapters] = useState<string[]>([
    "snmp_exporter",
    "http_json",
    "http_json_sandbox",
    "ssh",
    "ssh_command_sandbox",
  ]);

  const load = useCallback(async (query: string) => {
    const serial = ++requestSerial.current;
    setLoading(true);
    try {
      const requested = new URLSearchParams(window.location.search).get("device");
      const focused = !query && !category && requested && /^[0-9a-f-]{36}$/i.test(requested) ? requested : null;
      const [deviceData, counts] = await Promise.all([
        focused ? apiRequest<Device>(`/assets/devices/${encodeURIComponent(focused)}`).then(device => ({items: [device], next_cursor: null})) :
          apiRequest<DevicePage>(inventoryPagePath(query, category)),
        apiRequest<{total:number;categories:Record<string,number>}>("/assets/devices/summary"),
      ]);
      if (serial !== requestSerial.current) return;
      setDevices(deviceData.items);
      setFocusedDeviceId(focused);
      if (focused) {setExpandedDeviceId(focused); setDetailTab("status");}
      setNextCursor(deviceData.next_cursor);
      setCurrentCursor(undefined);
      setPreviousCursors([]);
      setSummary(counts);
      setHealthRefresh((value) => value + 1);
    } catch (error) {
      if (serial !== requestSerial.current) return;
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to load assets",
      });
    } finally {
      if (serial === requestSerial.current) setLoading(false);
    }
  }, [category]);

  useEffect(() => {
    let cancelled = false;
    apiRequest<{permissions: string[]; authorization_scope: {all?: boolean}}>("/auth/me").then((principal) => {
      if (cancelled) return;
      setCanWrite(principal.permissions.includes("*") || principal.permissions.includes("assets.write"));
      setCanActivate(principal.permissions.includes("*") || principal.permissions.includes("assets.activate"));
      setCanManageSSH(!!principal.authorization_scope?.all && ["capabilities.manage", "assets.read", "assets.activate", "tools.admin"].every(permission => principal.permissions.includes("*") || principal.permissions.includes(permission)));
    }).catch(() => { if (!cancelled) { setCanWrite(false); setCanActivate(false); setCanManageSSH(false); } });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (mode !== "add" && !expandedDeviceId) return;
    let cancelled = false;
    apiRequest<CredentialProfile[]>("/credential-profiles").then((profiles) => {
      if (!cancelled) setCredentials(profiles.filter((profile) => profile.enabled));
    }).catch(() => { if (!cancelled) setCredentials([]); });
    apiRequest<ActivationPolicy[]>("/assets/activation-policies?policy_status=published").then((policies) => {
      if (!cancelled) setActivationPolicies(policies);
    }).catch(() => { if (!cancelled) setActivationPolicies([]); });
    return () => { cancelled = true; };
  }, [mode, expandedDeviceId]);

  useEffect(() => {
    if (mode !== "add" && !expandedDeviceId) return;
    const controller = new AbortController();
    apiRequest<OnboardingWorker[]>("/collector-workers?limit=1000", {signal: controller.signal})
      .then(workers => {if (!controller.signal.aborted) setVerificationWorkers(workers);})
      .catch(() => {if (!controller.signal.aborted) setVerificationWorkers(null);});
    return () => controller.abort();
  }, [mode, expandedDeviceId]);

  const visibleIds = devices.slice(0, 50).map((device) => device.id).join(",");
  useEffect(() => {
    if (mode === "add" || !visibleIds) return;
    let cancelled = false;
    const controller = new AbortController();
    const serial = requestSerial.current;
    async function refreshHealth() {
      const params = new URLSearchParams();
      visibleIds.split(",").forEach((id) => params.append("device_ids", id));
      try {
        const page = await apiRequest<{items:DeviceHealth[]}>(`/assets/devices/health?${params}`, {signal:controller.signal});
        if (!cancelled && serial === requestSerial.current) setHealth(Object.fromEntries(page.items.map((item) => [item.device_id, item])));
      } catch {
        if (!cancelled && serial === requestSerial.current) setHealth({});
      }
    }
    void refreshHealth();
    const timer = window.setInterval(() => void refreshHealth(), 30000);
    return () => { cancelled = true; controller.abort(); window.clearInterval(timer); };
  }, [visibleIds, healthRefresh, mode]);

  useEffect(() => {
    const timeoutId = window.setTimeout(
      () => void load(search.trim()),
      search ? 300 : 0,
    );
    return () => window.clearTimeout(timeoutId);
  }, [load, search]);

  async function loadMoreDevices() {
    if (!nextCursor || loading || loadingMore) return;
    const serial = requestSerial.current;
    setLoadingMore(true);
    try {
      const page = await apiRequest<DevicePage>(
        inventoryPagePath(search.trim(), category, nextCursor),
      );
      if (serial !== requestSerial.current) return;
      setPreviousCursors((current) => [...current, currentCursor || ""]);
      setCurrentCursor(nextCursor);
      setDevices(page.items);
      setHealth({});
      setNextCursor(page.next_cursor);
    } catch (error) {
      if (serial !== requestSerial.current) return;
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to load more devices",
      });
    } finally {
      setLoadingMore(false);
    }
  }

  async function previousPage() {
    if (!previousCursors.length || loadingMore) return;
    const serial = requestSerial.current;
    const cursor = previousCursors.at(-1) || undefined;
    setLoadingMore(true);
    try {
      const page = await apiRequest<DevicePage>(inventoryPagePath(search.trim(), category, cursor));
      if (serial !== requestSerial.current) return;
      setPreviousCursors((current) => current.slice(0,-1));
      setCurrentCursor(cursor); setDevices(page.items); setHealth({}); setNextCursor(page.next_cursor);
    } catch (error) { setMessage({tone:"error",text:error instanceof Error ? error.message : "Unable to load previous page"}); }
    finally { setLoadingMore(false); }
  }

  function replaceVisibleDevice(updated: Device) {
    setDevices((current) => current.map((item) =>
      item.id === updated.id ? updated : item,
    ));
  }

  useEffect(() => {
    const waiting = devices.filter((device) => device.connections.some((connection) =>
      ["pending", "running"].includes(connection.verification_status))).slice(0, 10);
    if (!waiting.length) return;
    let cancelled = false;
    const serial = requestSerial.current;
    const timer = setTimeout(() => {
      Promise.all(waiting.map((device) => apiRequest<Device>(`/assets/devices/${device.id}`))).then((updated) => {
        if (cancelled || serial !== requestSerial.current) return;
        const byId = new Map(updated.map((device) => [device.id, device]));
        setDevices((current) => current.map((device) => byId.get(device.id) || device));
      }).catch(() => { /* Explicit Refresh remains available if polling fails. */ });
    }, 3000);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [devices]);

  async function refreshVisibleDevice(deviceId: string) {
    const updated = await apiRequest<Device>(`/assets/devices/${deviceId}`);
    replaceVisibleDevice(updated);
  }

  function toggleProtocol(protocol: Protocol) {
    setSelectedProtocols((current) =>
      current.includes(protocol)
        ? current.filter((item) => item !== protocol)
        : [...current, protocol],
    );
  }

  function toggleAdapter(adapter: string) {
    setAllowedAdapters((current) =>
      current.includes(adapter)
        ? current.filter((item) => item !== adapter)
        : [...current, adapter],
    );
  }

  async function createCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving("credential");
    setMessage(null);
    try {
      const created = await apiRequest<CredentialProfile>("/credential-profiles", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: credentialName,
          provider: credentialProvider,
          secret_ref: secretRef,
          allowed_adapters: allowedAdapters,
          worker_selector: { site: credentialSite },
          created_by: "assets.operator",
        }),
      });
      if (created.enabled) setCredentials((current) => [...current, created]);
      setCredentialName("");
      setMessage({ tone: "success", text: "Credential reference created." });
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to create credential",
      });
    } finally {
      setSaving(null);
    }
  }

  async function onboardDevice(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (selectedProtocols.length === 0) {
      setMessage({ tone: "error", text: "Select at least one monitoring method." });
      return;
    }
    const unavailable = selectedProtocols.find(protocol => !(protocol === "ssh" && nativeSSH) && verificationMethodAvailable(
      verificationWorkers, protocolOptions.find(item => item.value === protocol)!.adapter, site) === false);
    if (unavailable) {
      setMessage({tone: "error", text: `No online Collector advertises ${unavailable.replaceAll("_", " ")} verification at this site. Deselect it or configure a compatible Collector.`});
      return;
    }
    const invalidProtocol = selectedProtocols.find((protocol) =>
      !credentialReferenceEligible(
        credentials,
        protocolOptions.find((option) => option.value === protocol)?.adapter || "",
        site,
        connectionCredentials[protocol] || "",
      ),
    );
    if (invalidProtocol) {
      setMessage({
        tone: "error",
        text: `The ${invalidProtocol.replaceAll("_", " ")} credential is not eligible for site ${site}. Select another reference or leave it blank.`,
      });
      return;
    }
    setSaving("device");
    setMessage(null);
    try {
      const connections = selectedProtocols.map((protocol) => ({
        protocol,
        port: ports[protocol] ? Number(ports[protocol]) : null,
        credential_profile_ref: connectionCredentials[protocol] || null,
        worker_selector: site.trim() ? { site: site.trim() } : {},
        configuration: protocol === "ssh" && nativeSSH ? {verification_mode: "studio"} : {},
      }));
      await apiRequest<Device>("/assets/devices", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name,
          kind,
          management_ip: managementIp,
          vendor: vendor || null,
          model: model || null,
          site: site.trim() || null,
          location,
          labels: parseLabels(labels),
          connections,
          request_monitoring: requestMonitoring,
          created_by: "assets.operator",
        }),
      });
      setName("");
      setManagementIp("");
      setVendor("");
      setModel("");
      setMessage({
        tone: "success",
        text: selectedProtocols.every(protocol => protocol === "ssh" && nativeSSH)
          ? "Device and SSH connection registered. No network check was queued; test a selected MCP tool in Studio."
          : "Device saved. Collector methods are queued for verification; native SSH remains on demand in Studio.",
      });
      await load(search.trim());
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to onboard device",
      });
    } finally {
      setSaving(null);
    }
  }

  async function saveDeviceMetadata(device: Device, draft: DeviceMetadataDraft) {
    setSaving(`metadata:${device.id}`);
    setMessage(null);
    try {
      const updated = await apiRequest<Device>(
        `/assets/devices/${device.id}/metadata`,
        {
          method: "PATCH",
          body: JSON.stringify({
            ...draft,
            expected_revision: device.revision,
            actor: "assets.operator",
          }),
        },
      );
      replaceVisibleDevice(updated);
      setMessage({ tone: "success", text: `${updated.name} metadata saved.` });
    } catch (error) {
      if (error instanceof APIError && error.status === 409) {
        try {
          await refreshVisibleDevice(device.id);
          setMessage({
            tone: "error",
            text: "Another operator changed this device. Current values are loaded; review them before saving again.",
          });
        } catch {
          setMessage({
            tone: "error",
            text: "Another operator changed this device. Refresh the page before saving again.",
          });
        }
        return;
      }
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to save device metadata",
      });
    } finally {
      setSaving(null);
    }
  }

  async function changeConnectionState(device: Device, connection: DeviceConnection) {
    const enabled = connection.enabled === false;
    const onDemand = connection.configuration.verification_mode === "studio";
    if (!window.confirm(enabled ?
      onDemand ? "Enable this on-demand SSH connection? No network check is queued. Review and test the tool in Studio before installation." :
      "Enable this connection and request fresh verification? Continuous monitoring stays disabled until you approve it again." :
      "Disable this connection? This stops new verification and withdraws its continuous monitoring. Previous history is retained; disabling is not fault recovery.")) return;
    setSaving(`connection-state:${connection.id}`);
    setMessage(null);
    try {
      const updated = await apiRequest<Device>(`/assets/devices/${device.id}/connections/${connection.id}/enabled`, {
        method: "PATCH", body: JSON.stringify({expected_revision: device.revision, enabled,
          actor: "assets.operator", reason: enabled ? "Operator enabled this connection for fresh verification." : "Operator disabled this optional connection and withdrew its monitoring."}),
      });
      replaceVisibleDevice(updated);
      setMessage({tone: "success", text: enabled ? onDemand ? "SSH enabled for on-demand Studio tests; no network check was queued." : "Connection enabled; fresh verification is queued. Monitoring needs a new approval." : "Connection disabled. Verification and collection history are retained."});
    } catch (error) {
      if (error instanceof APIError && error.status === 409) await refreshVisibleDevice(device.id).catch(() => undefined);
      setMessage({tone: "error", text: error instanceof Error ? error.message : "Connection state could not be changed."});
    } finally {setSaving(null);}
  }

  async function loadVerificationHistory(device: Device, connection: DeviceConnection) {
    setSaving(`history:${connection.id}`);
    try {
      const rows = await apiRequest<VerificationRecord[]>(`/assets/devices/${device.id}/connections/${connection.id}/preflights?limit=20`);
      setVerificationHistory(current => ({...current, [connection.id]: rows}));
    } catch (error) {
      setMessage({tone: "error", text: error instanceof Error ? error.message : "Verification history could not be loaded."});
    } finally {setSaving(null);}
  }

  async function retryConnection(device: Device, connection: DeviceConnection) {
    const reason = window.prompt(
      `Why should ${device.name} ${connection.protocol.replaceAll("_", " ")} be verified again?`,
    );
    if (!reason?.trim()) return;
    setSaving(`retry:${connection.id}`);
    setMessage(null);
    try {
      const updated = await apiRequest<Device>(
        `/assets/devices/${device.id}/connections/${connection.id}/verification/retry`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            actor: "assets.operator",
            reason: reason.trim(),
          }),
        },
      );
      replaceVisibleDevice(updated);
      setMessage({
        tone: "success",
        text: `${device.name} ${connection.protocol.replaceAll("_", " ")} queued for verification.`,
      });
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to retry verification",
      });
    } finally {
      setSaving(null);
    }
  }

  async function previewActivation(
    device: Device,
    connection: DeviceConnection,
    fallbackPolicyId?: string,
  ) {
    const policyId = fallbackPolicyId || selectedPolicies[connection.id];
    if (!policyId) {
      setMessage({ tone: "error", text: "Select an activation policy first." });
      return;
    }
    setSaving(`preview:${connection.id}`);
    setMessage(null);
    try {
      const plan = await apiRequest<ActivationPlan>(
        `/assets/devices/${device.id}/connections/${connection.id}/activation/preview`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ policy_id: policyId }),
        },
      );
      setSelectedPolicies((current) => ({ ...current, [connection.id]: policyId }));
      setActivationPlans((current) => ({ ...current, [connection.id]: plan }));
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to preview activation",
      });
    } finally {
      setSaving(null);
    }
  }

  async function approveActivation(device: Device, connection: DeviceConnection) {
    const plan = activationPlans[connection.id];
    if (!plan) return;
    const reason = window.prompt(
      `Why should ${plan.policy_name} be activated for ${device.name}?`,
      "Activate verified monitoring intent",
    );
    if (!reason?.trim()) return;
    setSaving(`approve:${connection.id}`);
    setMessage(null);
    try {
      await apiRequest(
        `/assets/devices/${device.id}/connections/${connection.id}/activation/approve`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            policy_id: plan.policy_id,
            expected_plan_hash: plan.plan_hash,
            actor: "assets.operator",
            reason: reason.trim(),
          }),
        },
      );
      setActivationPlans((current) => {
        const next = { ...current };
        delete next[connection.id];
        return next;
      });
      setMessage({
        tone: "success",
        text: `${plan.policy_name} activated for ${device.name}.`,
      });
      await refreshVisibleDevice(device.id);
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to approve activation",
      });
    } finally {
      setSaving(null);
    }
  }

  async function deactivateCapability(
    device: Device,
    connection: DeviceConnection,
    activation: ConnectionActivation,
  ) {
    const reason = window.prompt(
      `Why should ${activation.capability_key} be deactivated for ${device.name}?`,
    );
    if (!reason?.trim()) return;
    setSaving(`deactivate:${activation.id}`);
    setMessage(null);
    try {
      await apiRequest(
        `/assets/devices/${device.id}/connections/${connection.id}/activations/${activation.id}/deactivate`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            actor: "assets.operator",
            reason: reason.trim(),
          }),
        },
      );
      setMessage({
        tone: "success",
        text: `${activation.capability_key} deactivated for ${device.name}.`,
      });
      await refreshVisibleDevice(device.id);
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to deactivate monitoring",
      });
    } finally {
      setSaving(null);
    }
  }

  return (
    <div className="min-h-screen bg-[#f3f4f7] text-[#2c384a]">
      <header data-text-surface="dark" className="border-b border-[#d8dbe0] bg-[#303c54] text-white">
        <div className="mx-auto flex min-h-16 max-w-[1500px] items-center gap-4 px-4 sm:px-6 xl:px-8">
          <Link
            href="/"
            className="grid size-9 place-items-center rounded-md bg-[#5856d6]"
            aria-label="Back to operations"
          >
            <Activity className="size-[18px]" />
          </Link>
          <div>
            <p className="text-sm font-semibold">iCheck Assets</p>
            <p className="text-xs text-muted-foreground">Inventory and live monitoring status</p>
          </div>
          <Badge className="ml-auto border-[#7a79df]/50 bg-[#5856d6]/30 text-[#d9d8ff]">
            Operator managed
          </Badge>
        </div>
      </header>

      <main className="mx-auto max-w-[1500px] px-4 py-6 sm:px-6 xl:px-8">
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <Link
              href="/"
              className="mb-3 inline-flex items-center gap-1.5 text-xs font-medium text-[#5856d6]"
            >
              <ArrowLeft className="size-3.5" /> Operations workspace
            </Link>
            <h1 className="flex items-center gap-3 text-2xl font-semibold tracking-[-0.02em]">
              <span className="grid size-10 place-items-center rounded-lg bg-[#e9e8fb] text-[#5856d6]">
                <Network className="size-5" />
              </span>
              {mode === "add" ? "Add device" : "Assets"}
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
              {mode === "add" ? "Enroll a device using saved credentials. Physical location is optional; collection must be verified." :
                "Browse devices by type, check current collection status, and assign published monitoring templates. Status refreshes every 30 seconds."}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {focusedDeviceId && <Button variant="outline" onClick={() => {
              const url = new URL(window.location.href); url.searchParams.delete("device");
              window.history.replaceState(null, "", url); setFocusedDeviceId(null); setExpandedDeviceId(null); void load("");
            }}>Show all devices</Button>}
            <Button asChild variant="outline"><Link href="/monitoring">Monitoring</Link></Button>
            <Button asChild className="bg-[#5856d6] text-white hover:bg-[#4947ad]">
              <Link href={mode === "add" ? "/assets/devices" : "/assets/devices/add"}><Plus className="size-4" /> {mode === "add" ? "Device inventory" : "Add device"}</Link>
            </Button>
            <Button asChild variant="outline" className="border-[#b1b7c1] bg-white text-[#4f5d73]">
              <Link href="/assets/interfaces">Collected interfaces</Link>
            </Button>
            <Button asChild variant="outline" className="border-[#b1b7c1] bg-white text-[#4f5d73]">
              <Link href="/assets/activation-policies">
                Activation policies
              </Link>
            </Button>
            <Button asChild variant="outline" className="border-[#b1b7c1] bg-white text-[#4f5d73]">
              <Link href="/assets/endpoints">
                <MonitorCog className="size-4" /> Observed endpoints
              </Link>
            </Button>
            <Button
              variant="outline"
              disabled={loading}
              onClick={() => {
                setLoading(true);
                void load(search.trim());
              }}
              className="border-[#b1b7c1] bg-white text-[#4f5d73]"
            >
              <RefreshCw className={cn("size-4", loading && "animate-spin")} /> Refresh
            </Button>
          </div>
        </div>

        {message ? (
          <div
            className={cn(
              "mb-5 flex items-center gap-2 rounded-md border px-4 py-3 text-sm",
              message.tone === "success"
                ? "border-[#2eb85c]/30 bg-[#2eb85c]/10 text-[#166534]"
                : "border-[#e55353]/30 bg-[#e55353]/10 text-[#a52a2a]",
            )}
          >
            {message.tone === "success" ? (
              <CheckCircle2 className="size-4" />
            ) : (
              <XCircle className="size-4" />
            )}
            {message.text}
          </div>
        ) : null}

        {mode === "add" ? <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          <Card className="border-[#d8dbe0] bg-white shadow-sm">
            <CardHeader className="border-b border-[#e4e6e9]">
              <CardTitle className="flex items-center gap-2 text-base">
                <MonitorCog className="size-4 text-[#5856d6]" /> Add device
              </CardTitle>
              <CardDescription>
                Identity, placement, and one or more protocol-neutral monitoring intents.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={onboardDevice} className="space-y-5">
                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  <label>
                    <FieldLabel>Device name</FieldLabel>
                    <Input required value={name} onChange={(event) => setName(event.target.value)} placeholder="lab-fw-01" className={inputClass} />
                  </label>
                  <label>
                    <FieldLabel>Management IP</FieldLabel>
                    <Input required value={managementIp} onChange={(event) => setManagementIp(event.target.value)} placeholder="10.10.0.1" className={cn(inputClass, "font-mono")} />
                  </label>
                  <label>
                    <FieldLabel>Device type</FieldLabel>
                    <select value={kind} onChange={(event) => setKind(event.target.value)} className={selectClass}>
                      {deviceKinds.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                    </select>
                  </label>
                  <label>
                    <FieldLabel>Site / legacy group (optional)</FieldLabel>
                    <Input value={site} maxLength={128} onChange={(event) => setSite(event.target.value)} placeholder="Leave blank if not assigned" className={inputClass} />
                  </label>
                  <label>
                    <FieldLabel>Vendor</FieldLabel>
                    <Input value={vendor} onChange={(event) => setVendor(event.target.value)} placeholder="Cisco, Fortinet, Linux…" className={inputClass} />
                  </label>
                  <label>
                    <FieldLabel>Model</FieldLabel>
                    <Input value={model} onChange={(event) => setModel(event.target.value)} placeholder="Optional" className={inputClass} />
                  </label>
                  <label className="sm:col-span-2 lg:col-span-3">
                    <FieldLabel>Labels as key=value, comma separated</FieldLabel>
                    <Input value={labels} onChange={(event) => setLabels(event.target.value)} placeholder="environment=lab,role=edge" className={inputClass} />
                  </label>
                </div>

                <DeviceLocationFields value={location} onChange={setLocation} />
                <label className="flex items-start gap-2 text-sm">
                  <input type="checkbox" checked={requestMonitoring} onChange={event => setRequestMonitoring(event.target.checked)} className="mt-1" />
                  <span>Request continuous SNMP monitoring after verification
                    <span className="mt-1 block text-xs text-muted-foreground">Managed SNMP credentials only. Uses existing gateway permissions, a 30-second interval and a seven-day lifetime; renew or withdraw under Manage.</span>
                  </span>
                </label>

                <div className="border-t border-[#e4e6e9] pt-5">
                  <div className="mb-3">
                    <h2 className="text-sm font-semibold">Monitoring methods</h2>
                    <p className="mt-1 text-xs text-muted-foreground">
                    Select a saved credential profile. Create SNMP, Windows, HTTPS or SSH credentials securely in <a href="/settings/credentials" className="text-violet-700 underline">Device credentials</a>; never enter secrets in AI chat.
                    </p>
                  </div>
                  <div className="grid gap-3 md:grid-cols-2">
                    <p className="mb-3 text-xs text-muted-foreground">Ping is optional and is not selected automatically. A successful ping or open port does not prove metric collection or authentication.</p>
                    {verificationWorkers === null ? <p className="mb-3 text-xs text-muted-foreground">Collector support is not confirmed. Verification can remain pending until a compatible Collector is online.</p> : null}
                    {protocolOptions.map((protocol) => {
                      const selected = selectedProtocols.includes(protocol.value);
                      const available = protocol.value === "ssh" && nativeSSH ? true : verificationMethodAvailable(verificationWorkers, protocol.adapter, site);
                      const compatibleCredentials = eligibleCredentialProfiles(
                        credentials, protocol.adapter, site,
                      );
                      const selectedCredential = connectionCredentials[protocol.value] || "";
                      const staleCredential = Boolean(selectedCredential) && !credentialReferenceEligible(
                        credentials, protocol.adapter, site, selectedCredential,
                      );
                      return (
                        <div key={protocol.value} className={cn("rounded-md border p-3", selected ? "border-[#5856d6]/40 bg-[#e9e8fb]/40" : "border-[#d8dbe0]")}>
                          <label className="flex cursor-pointer items-start gap-3">
                            <input type="checkbox" checked={selected} disabled={available === false && !selected} onChange={() => toggleProtocol(protocol.value)} className="mt-1 size-4 accent-[#5856d6]" />
                            <span>
                              <span className="block text-sm font-medium">{protocol.label}</span>
                              <span className="mt-0.5 block text-xs text-muted-foreground">{protocol.description}</span>
                            </span>
                          </label>
                          {available === false ? <p className="mt-2 text-xs text-[#a52a2a]">No online Collector advertises this verification method at the selected site. Configure one or deselect this method.</p> : null}
                          {protocol.value === "ssh" ? <label className="mt-2 flex items-start gap-2 text-xs"><input type="checkbox" checked={nativeSSH} onChange={event => setNativeSSH(event.target.checked)} />Register for native MCP tools only. No Collector check is queued. Reuse a saved SSH password, then confirm the device fingerprint and test in Studio. An unassigned device keeps the selected credential’s connection scope.</label> : null}
                          {selected ? (
                            <div className="mt-3 grid grid-cols-[90px_1fr] gap-2">
                              <Input aria-label={`${protocol.label} port`} disabled={protocol.value === "icmp"} value={ports[protocol.value]} onChange={(event) => setPorts((current) => ({ ...current, [protocol.value]: event.target.value }))} placeholder="Port" className={cn(inputClass, "font-mono text-xs")} />
                              <select aria-label={`${protocol.label} credential`} value={selectedCredential} onChange={(event) => setConnectionCredentials((current) => ({ ...current, [protocol.value]: event.target.value }))} className={selectClass}>
                                <option value="">No credential profile</option>
                                {staleCredential ? <option value={selectedCredential} disabled>Selected reference is unavailable at this site</option> : null}
                                {compatibleCredentials.map((credential) => <option key={credential.id} value={credential.id}>{credential.name}</option>)}
                              </select>
                            </div>
                          ) : null}
                          {selected && staleCredential ? <p role="alert" className="mt-2 text-xs text-[#a52a2a]">Choose a credential allowed for this site and method before enrolling.</p> : null}
                        </div>
                      );
                    })}
                  </div>
                </div>

                <Button disabled={saving === "device" || !canWrite || selectedProtocols.some(protocol => !(protocol === "ssh" && nativeSSH) && verificationMethodAvailable(
                  verificationWorkers, protocolOptions.find(item => item.value === protocol)!.adapter, site) === false)}>
                  <Plus /> Enroll device
                </Button>
              </form>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] bg-white shadow-sm">
            <CardHeader className="border-b border-[#e4e6e9]">
              <CardTitle className="flex items-center gap-2 text-base">
                <KeyRound className="size-4 text-[#5856d6]" /> Credential reference
              </CardTitle>
              <CardDescription>
                Create a scoped reference before assigning it to a device.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={createCredential} className="space-y-4">
                <label>
                  <FieldLabel>Profile name</FieldLabel>
                  <Input required value={credentialName} onChange={(event) => setCredentialName(event.target.value)} placeholder="lab-network-readonly" className={inputClass} />
                </label>
                <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
                  <label>
                    <FieldLabel>Secret provider</FieldLabel>
                    <select value={credentialProvider} onChange={(event) => setCredentialProvider(event.target.value)} className={selectClass}>
                      <option value="vault">Vault / external</option>
                      <option value="environment">Environment</option>
                    </select>
                  </label>
                  <label>
                    <FieldLabel>Site scope</FieldLabel>
                    <Input required value={credentialSite} onChange={(event) => setCredentialSite(event.target.value)} className={inputClass} />
                  </label>
                </div>
                <label>
                  <FieldLabel>Secret reference</FieldLabel>
                  <Input required value={secretRef} onChange={(event) => setSecretRef(event.target.value)} placeholder="kv/lab/network-readonly" className={cn(inputClass, "font-mono text-xs")} />
                </label>
                <div>
                  <FieldLabel>Allowed adapters</FieldLabel>
                  <div className="grid grid-cols-2 gap-2">
                    {protocolOptions.filter((item) => item.adapter !== "icmp").flatMap((item) =>
                      activationAdapters[item.value].map((adapter) => (
                        <label key={adapter} className="flex items-center gap-2 rounded-md bg-[#f8f9fa] px-2.5 py-2 text-xs">
                          <input type="checkbox" checked={allowedAdapters.includes(adapter)} onChange={() => toggleAdapter(adapter)} className="accent-[#5856d6]" />
                          {item.label}{adapter !== item.adapter ? ` · ${adapter}` : ""}
                        </label>
                      )),
                    )}
                  </div>
                </div>
                <Button disabled={saving === "credential" || allowedAdapters.length === 0}>
                  <Plus /> Add reference
                </Button>
              </form>
              <div className="mt-5 space-y-2 border-t border-[#e4e6e9] pt-4">
                {credentials.slice(0, 6).map((credential) => (
                  <div key={credential.id} className="flex items-center gap-3 rounded-md bg-[#f8f9fa] px-3 py-2.5">
                    <ShieldCheck className="size-4 shrink-0 text-[#2eb85c]" />
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{credential.name}</p>
                      <p className="truncate font-mono text-[11px] text-muted-foreground">{credential.secret_ref}</p>
                    </div>
                  </div>
                ))}
                {credentials.length === 0 ? <p className="text-sm text-muted-foreground">No credential references available.</p> : null}
              </div>
            </CardContent>
          </Card>
        </div> : null}

        {mode === "add" ? <p className="mt-5 text-sm"><Link href="/assets/devices" className="text-[#5856d6] underline">Open device inventory and status</Link></p> : <>
        <nav aria-label="Device categories" className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-7">
          {assetCategories.map(([value, label]) => <button key={value} type="button" aria-pressed={category === value}
            onClick={() => { requestSerial.current += 1; setCategory(value); setDevices([]); setHealth({}); setNextCursor(null); setExpandedDeviceId(null); }}
            className={cn("rounded-lg border bg-white px-4 py-3 text-left shadow-sm", category === value ? "border-[#5856d6] ring-1 ring-[#5856d6]" : "border-[#d8dbe0]")}>
            <span className="block text-xs font-medium">{label}</span>
            <span className="mt-2 block text-xl font-semibold">{summary ? value ? summary.categories[value] || 0 : summary.total : "—"}</span>
          </button>)}
        </nav>
        <p className="mb-4 text-xs text-muted-foreground">Servers includes explicitly registered physical servers and Linux/Windows hosts. Wireless includes access points and controllers; observed client terminals have their own inventory.</p>
        <Card className="gap-0 border-[#d8dbe0] bg-white py-0 shadow-sm">
          <CardHeader className="border-b border-[#e4e6e9] px-5 py-4">
            <div>
              <CardTitle className="text-base">Device inventory</CardTitle>
              <CardDescription className="mt-1">Live collection status is separate from protocol enrollment. Unknown and stale evidence are never shown as Up.</CardDescription>
            </div>
            <div className="relative mt-3 w-full max-w-sm">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(event) => {
                  requestSerial.current += 1;
                  setSearch(event.target.value);
                  setDevices([]);
                  setNextCursor(null);
                  setExpandedDeviceId(null);
                  setLoading(true);
                }}
                placeholder="Search device, IP, type, site, or vendor"
                className={cn(inputClass, "pl-9")}
              />
            </div>
          </CardHeader>
          <CardContent className="px-0">
            <Table>
              <TableHeader>
                <TableRow className="bg-[#f8f9fa] hover:bg-[#f8f9fa]">
                  <TableHead className="pl-5">Device</TableHead>
                  <TableHead className="hidden sm:table-cell">Type / location</TableHead>
                  <TableHead className="hidden sm:table-cell">Monitoring</TableHead>
                  <TableHead className="hidden sm:table-cell">Live status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.map((device) => (
                  <Fragment key={device.id}>
                    <TableRow>
                      <TableCell className="pl-5 whitespace-normal">
                        <p className="text-sm font-medium">{deviceDisplayName(device)}</p>
                        <p className="mt-0.5 font-mono text-xs text-muted-foreground">{device.management_ip || "Management IP not set"}</p>
                        {device.discovered_name ? <p className="mt-0.5 text-xs text-muted-foreground">SNMP sysName: {device.discovered_name}</p> : null}
                        <div className="mt-2 space-y-2 sm:hidden">
                          <p className="text-xs capitalize text-muted-foreground">
                            {device.kind.replaceAll("_", " ")} · {formatDeviceLocation(device.location) || device.site || "Location not assigned"}
                          </p>
                          <div className="flex flex-wrap gap-1">
                            {device.connections.map((connection) => (
                              <Badge key={connection.id} variant="outline" className={cn("text-[10px]", statusClass(connection.verification_status))}>
                                {connection.protocol.replaceAll("_", " ")}
                                {connection.port ? `:${connection.port}` : ""}
                                {` · ${connection.verification_status}`}
                              </Badge>
                            ))}
                            {device.connections.length === 0 ? <span className="text-xs text-muted-foreground">No monitoring intent</span> : null}
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge className={healthTone(health[device.id]?.state)} title={health[device.id]?.reason}>
                              {healthLabel(health[device.id]?.state)}
                            </Badge>
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              aria-expanded={expandedDeviceId === device.id}
                              aria-controls={`device-details-${device.id}`}
                              className="h-7 border-[#c9cdd4] px-2 text-[11px]"
                              onClick={() => {setDetailTab("status"); setExpandedDeviceId((current) => current === device.id ? null : device.id);}}
                            >
                              {expandedDeviceId === device.id ? "Hide" : "Manage"}
                            </Button>
                            {canActivate ? <Button size="sm" variant="outline" className="h-7 px-2 text-[11px]" onClick={() => {setDetailTab("templates"); setExpandedDeviceId(device.id);}}>Apply template</Button> : null}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="hidden sm:table-cell">
                        <p className="text-sm capitalize">{device.kind.replaceAll("_", " ")}</p>
                        <p className="mt-0.5 text-xs text-muted-foreground">{formatDeviceLocation(device.location) || device.site || "Location not assigned"}</p>
                      </TableCell>
                      <TableCell className="hidden sm:table-cell">
                        <div className="flex max-w-md flex-wrap gap-1">
                          {device.connections.map((connection) => (
                            <Badge key={connection.id} variant="outline" className={cn("text-[10px]", statusClass(connection.verification_status))}>
                              {connection.protocol.replaceAll("_", " ")}
                              {connection.port ? `:${connection.port}` : ""}
                              {` · ${connection.verification_status}`}
                            </Badge>
                          ))}
                          {device.connections.length === 0 ? <span className="text-xs text-muted-foreground">No monitoring intent</span> : null}
                        </div>
                      </TableCell>
                      <TableCell className="hidden sm:table-cell">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge className={healthTone(health[device.id]?.state)} title={health[device.id]?.reason}>
                            {healthLabel(health[device.id]?.state)}
                          </Badge>
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            aria-expanded={expandedDeviceId === device.id}
                            aria-controls={`device-details-${device.id}`}
                            className="h-7 border-[#c9cdd4] px-2 text-[11px]"
                            onClick={() => {setDetailTab("status"); setExpandedDeviceId((current) => current === device.id ? null : device.id);}}
                          >
                            {expandedDeviceId === device.id ? "Hide" : "Manage"}
                          </Button>
                          {canActivate ? <Button size="sm" variant="outline" className="h-7 px-2 text-[11px]" onClick={() => {setDetailTab("templates"); setExpandedDeviceId(device.id);}}>Apply template</Button> : null}
                        </div>
                      </TableCell>
                    </TableRow>
                    {expandedDeviceId === device.id ? (
                      <TableRow id={`device-details-${device.id}`} className="bg-[#f8f9fa]/70 hover:bg-[#f8f9fa]/70">
                        <TableCell colSpan={4} className="px-5 py-4 whitespace-normal">
                          <nav aria-label={`Device sections for ${deviceDisplayName(device)}`} className="mb-4 flex flex-wrap gap-2">
                            {([ ["status", "Live status"], ["templates", "Monitoring templates"], ["settings", "Device settings"] ] as const).map(([tab,label]) =>
                              <Button key={tab} size="sm" variant="outline" aria-pressed={detailTab === tab} onClick={() => setDetailTab(tab)}>{label}</Button>)}
                            {device.connections.some((connection) => connection.protocol === "snmp") ?
                              <Button asChild size="sm" variant="outline">
                                <a href={networkDashboardHref(device.id)} aria-label={`Open ${deviceDisplayName(device)} network metrics in Grafana`}>Open in Grafana</a>
                              </Button> : null}
                          </nav>
                          {detailTab === "status" ? <div className="space-y-3"><DeviceLiveStatus health={health[device.id]} /><DeviceDashboards deviceId={device.id}/></div> : null}
                          {detailTab === "templates" ? <div className="mb-4 rounded border bg-white p-4 text-xs">
                            <h2 className="text-sm font-semibold">Apply a published monitoring template</h2>
                            <p className="mt-2 text-muted-foreground">Select a published collection policy below, preview its exact device binding, then approve it. Drafts and MIB proposals marked “External validation required” cannot be applied.</p>
                            <div className="mt-2 flex flex-wrap gap-4"><Link href="/assets/activation-policies" className="text-[#5856d6] underline">Published template policies</Link><Link href="/studio/artifacts" className="text-[#5856d6] underline">Capability library</Link><Link href="/studio" className="text-[#5856d6] underline">AI authoring</Link></div>
                          </div> : null}
                          {detailTab === "settings" && canWrite ? <>
                          <DeviceMetadataEditor
                            key={`${device.id}:${device.revision}`}
                            device={device}
                            saving={saving === `metadata:${device.id}`}
                            onSave={(draft) => saveDeviceMetadata(device, draft)}
                          />
                          <DeviceIdentityEditor
                            key={`identity:${device.id}:${device.revision}`}
                            device={device}
                            credentials={credentials}
                            onCommitted={(updated) => {
                              replaceVisibleDevice(updated);
                              setMessage({
                                tone: "success",
                                text: `${updated.name} identity corrected; its connections now require fresh verification.`,
                              });
                            }}
                            onConflict={async () => {
                              await refreshVisibleDevice(device.id);
                              setMessage({
                                tone: "error",
                                text: "Device state changed. Review the latest values and preview the correction again.",
                              });
                            }}
                          />
                          </> : null}
                          {detailTab === "settings" && !canWrite ? <p className="mb-3 text-xs text-muted-foreground">Read-only device access. Settings changes require asset-write permission.</p> : null}
                          {detailTab === "settings" && canWrite && !device.connections.some(connection => connection.protocol === "ssh") ? <DeviceNativeSSH
                            key={`native-ssh:${device.id}:${device.revision}`} device={device} onSaved={async () => {
                              await refreshVisibleDevice(device.id);
                              setMessage({tone: "success", text: "SSH access saved. Review its fingerprint in device settings before first use."});
                            }} /> : null}
                          {detailTab !== "status" ? <div className="grid gap-3 lg:grid-cols-2">
                            {device.connections.map((connection) => {
                              const hasEvidence = Object.keys(connection.last_verification_evidence).length > 0;
                              const onDemand = connection.protocol === "ssh" && connection.configuration.verification_mode === "studio";
                              const retryable = !onDemand && connection.enabled !== false && ["failed", "verified"].includes(connection.verification_status);
                              const verificationAvailable = onDemand ? true : verificationMethodAvailable(verificationWorkers, connection.adapter_type, device.site || "");
                              const compatiblePolicies = activationPolicies.filter(
                                (policy) =>
                                  policy.protocol === connection.protocol &&
                                  activationAdapters[connection.protocol].includes(policy.adapter_type),
                              );
                              const selectedPolicyId =
                                selectedPolicies[connection.id] ||
                                compatiblePolicies.find(
                                  (policy) =>
                                    !connection.activations.some(
                                      (activation) =>
                                        activation.status === "active" &&
                                        activation.policy_id === policy.id,
                                    ),
                                )?.id ||
                                compatiblePolicies[0]?.id;
                              const activationPlan = activationPlans[connection.id];
                              const activeActivationCount = connection.activations.filter(
                                (activation) => activation.status === "active",
                              ).length;
                              return (
                                <div key={connection.id} className="rounded-md border border-[#d8dbe0] bg-white p-3">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <p className="text-sm font-semibold capitalize">{connection.protocol.replaceAll("_", " ")}</p>
                                    <Badge className={cn("text-[10px]", statusClass(connection.verification_status))}>{connection.verification_status === "not_requested" ? "Registered · untested" : connection.verification_status}</Badge>
                                    {detailTab === "settings" && canWrite ? <Button type="button" size="sm" variant="outline"
                                      disabled={!!saving || (connection.enabled === false && verificationAvailable === false)}
                                      onClick={() => void changeConnectionState(device, connection)} className="h-7 text-[11px]">
                                      {connection.enabled === false ? "Enable connection" : "Disable connection"}
                                    </Button> : null}
                                    <Link href={onDemand ? "/studio" : `/assets/activation-policies?device_id=${encodeURIComponent(device.id)}&protocol=${connection.protocol}`} className="ml-auto text-[11px] font-medium text-[#5856d6] hover:underline">{onDemand ? "Test MCP tools in Studio" : "Draft policy with AI"}</Link>
                                    {retryable ? (
                                      <Button
                                        type="button"
                                        size="sm"
                                        variant="outline"
                                        disabled={saving === `retry:${connection.id}`}
                                        onClick={() => void retryConnection(device, connection)}
                                        className="ml-auto h-7 border-[#c9cdd4] px-2 text-[11px]"
                                      >
                                        <RotateCcw className={cn("size-3", saving === `retry:${connection.id}` && "animate-spin")} /> Reverify
                                      </Button>
                                    ) : null}
                                  </div>
                                  {detailTab === "settings" ? <>
                                  {connection.protocol === "ssh" && connection.enabled !== false && canManageSSH ? <DeviceSSHAccess connection={connection.id} /> : null}
                                  {verificationAvailable === false ? <p className="mt-2 text-xs text-[#a52a2a]">No online Collector advertises this verification method at this site. Disable an unused optional connection or configure a compatible Collector.</p> : null}
                                  {connection.enabled === false ? <p className="mt-2 text-xs text-muted-foreground">This connection is disabled. Past diagnostics are historical, not a current health verdict.</p> : null}
                                  <details className="mt-2 text-xs"><summary className="cursor-pointer">Verification history</summary>
                                    <Button type="button" size="sm" variant="outline" disabled={saving === `history:${connection.id}`} onClick={() => void loadVerificationHistory(device, connection)} className="my-2 h-7 text-[11px]">Load last 20 checks</Button>
                                    {verificationHistory[connection.id]?.length === 0 ? <p>No retained checks.</p> : null}
                                    {verificationHistory[connection.id]?.map(row => <p key={row.id} className="mt-1 break-words">
                                      {new Date(row.finished_at || row.started_at).toLocaleString()} · {row.status}
                                      {row.evidence.verification_level ? ` · ${row.evidence.verification_level.replaceAll("_", " ")}` : ""}
                                      {row.evidence.authentication_tested === false ? " · authentication not tested" : ""}
                                      {row.error ? ` · ${row.error}` : ""}
                                    </p>)}
                                  </details>
                                  <p className="mt-1 text-xs text-muted-foreground">
                                    {connection.adapter_type}{connection.port ? ` on port ${connection.port}` : ""}
                                  </p>
                                  {connection.last_verification_error ? (
                                    <p className="mt-2 rounded bg-[#e55353]/8 px-2 py-1.5 text-xs text-[#a52a2a]">{connection.last_verification_error}</p>
                                  ) : null}
                                  {connection.last_verification_evidence.diagnostic && typeof connection.last_verification_evidence.diagnostic === "object" ? (
                                    <p className="mt-1 text-xs text-muted-foreground">Root cause: {String((connection.last_verification_evidence.diagnostic as Record<string, unknown>).code || "Unknown")}. {String((connection.last_verification_evidence.diagnostic as Record<string, unknown>).next_action || "")}</p>
                                  ) : null}
                                  {connection.enabled !== false && connection.protocol === "snmp" ? <SNMPConfiguration key={`snmp:${connection.id}:${device.revision}`}
                                    modules={connection.configuration?.modules || ["if_mib"]}
                                    pending={connection.verification_status === "running"}
                                    onSave={async (modules) => {
                                      const updated = await apiRequest<Device>(`/assets/devices/${device.id}/connections/${connection.id}/snmp-configuration`, {
                                        method: "PATCH", body: JSON.stringify({expected_revision: device.revision, modules,
                                          actor: "assets.operator", reason: "Operator corrected installed SNMP monitoring modules."}),
                                      });
                                      replaceVisibleDevice(updated);
                                      setMessage({tone: "success", text: "SNMP modules saved. Identity verification is queued; continuous monitoring needs fresh approval."});
                                    }} /> : null}
                                  {connection.last_verified_at ? (
                                    <div className="mt-3 border-t border-[#eceef0] pt-2">
                                      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                                        {connection.last_verification_worker_id ? <span>Worker {connection.last_verification_worker_id.slice(0, 8)}</span> : null}
                                        <span>{new Date(connection.last_verified_at).toLocaleString()}</span>
                                        {connection.last_verification_latency_ms !== null ? <span>{connection.last_verification_latency_ms} ms</span> : null}
                                      </div>
                                      {hasEvidence ? (
                                        <pre role="region" aria-label={`Verification evidence for ${device.name} (${connection.protocol})`} tabIndex={0} className="mt-2 max-h-28 overflow-auto rounded bg-[#f3f4f7] p-2 font-mono text-[11px] text-[#4f5d73] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#5856d6]">{JSON.stringify(connection.last_verification_evidence, null, 2)}</pre>
                                      ) : (
                                        <p className="mt-2 text-xs text-muted-foreground">No evidence reported yet.</p>
                                      )}
                                    </div>
                                  ) : (
                                    <p className="mt-3 text-xs text-muted-foreground">{connection.enabled === false ?
                                      "Connection disabled; no verification is queued." : onDemand ? "On-demand SSH: no Collector verification is queued. Confirm the device fingerprint in Studio, then test a selected tool." : verificationAvailable === false ?
                                      "Verification cannot start until a compatible Collector is online." :
                                      "Waiting for a matching site worker to claim this preflight."}</p>
                                  )}
                                  </> : null}
                                  {connection.enabled !== false && connection.protocol === "https_api" && detailTab === "settings" ? <HTTPConfiguration key={`http:${connection.id}:${device.revision}`}
                                    spec={connection.configuration?.http_monitor} port={connection.port} credential={connection.credential_profile_ref}
                                    status={connection.verification_status} proof={connection.last_verification_evidence} canWrite={canWrite}
                                    onSave={async (http_monitor, port, credential_profile_ref) => {
                                      const updated = await apiRequest<Device>(`/assets/devices/${device.id}/connections/${connection.id}/http-configuration`, {
                                        method: "PATCH", body: JSON.stringify({expected_revision: device.revision, http_monitor, port, credential_profile_ref,
                                          actor: "assets.operator", reason: "Operator saved a read-only HTTP monitoring template and requested its metric test."}),
                                      });
                                      replaceVisibleDevice(updated);
                                      setMessage({tone: "success", text: "HTTP template saved. Metric test is queued; enable continuous collection after it succeeds."});
                                    }} /> : null}
                                  {connection.protocol === "snmp" || connection.protocol === "windows_exporter" || connection.protocol === "node_exporter" || connection.protocol === "cadvisor" || connection.protocol === "vmware_exporter" || connection.protocol === "https_api" ? (
                                    <details className="mt-3 rounded border p-3"><summary className="cursor-pointer text-xs font-semibold">Continuous collection</summary>
                                    <DeviceMonitoring
                                      key={`monitoring:${connection.id}:${device.identity_revision}:${connection.last_verified_at}`}
                                      deviceId={device.id} connectionId={connection.id} protocol={connection.protocol} configuration={connection.configuration}
                                    />
                                    </details>
                                  ) : null}
                                  {detailTab === "templates" ?
                                  <div className="mt-3 border-t border-[#eceef0] pt-3">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <p className="text-xs font-semibold text-[#4f5d73]">Published monitoring templates</p>
                                      {activeActivationCount > 0 ? (
                                        <Badge className="border-[#2eb85c]/30 bg-[#2eb85c]/10 text-[10px] text-[#166534]">
                                          {activeActivationCount} active
                                        </Badge>
                                      ) : null}
                                    </div>

                                    {connection.activations.length > 0 ? (
                                      <div className="mt-2 space-y-2">
                                        {connection.activations.map((activation) => {
                                          const policy = activationPolicies.find(
                                            (item) => item.id === activation.policy_id,
                                          );
                                          return (
                                            <div
                                              key={activation.id}
                                              className={cn(
                                                "rounded-md border p-2.5",
                                                activation.status === "active"
                                                  ? "border-[#2eb85c]/20 bg-[#2eb85c]/5"
                                                  : "border-[#d8dbe0] bg-[#f8f9fa]",
                                              )}
                                            >
                                              <div className="flex flex-wrap items-center gap-2">
                                                <p className="text-xs font-medium text-[#344054]">
                                                  {policy
                                                    ? `${policy.name} v${policy.version}`
                                                    : activation.capability_key}
                                                </p>
                                                <Badge className={cn("text-[10px]", statusClass(activation.status))}>
                                                  {activation.status}
                                                </Badge>
                                                <Badge className={cn("text-[10px]", statusClass(activation.runtime_status || "pending"))}>
                                                  {(activation.runtime_status || "pending").replaceAll("_", " ")}
                                                </Badge>
                                              </div>
                                              <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                                                Deployment {activation.deployment_id?.slice(0, 12) || "unavailable"}
                                              </p>
                                              {activation.health_reason ? (
                                                <p className="mt-1.5 text-[11px] text-muted-foreground">{activation.health_reason}</p>
                                              ) : null}
                                              <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-muted-foreground">
                                                {activation.last_success_at ? (
                                                  <span>Last success {new Date(activation.last_success_at).toLocaleString()}</span>
                                                ) : null}
                                                {activation.last_failure_at ? (
                                                  <span>Last failure {new Date(activation.last_failure_at).toLocaleString()}</span>
                                                ) : null}
                                                {activation.consecutive_failures ? (
                                                  <span>{activation.consecutive_failures} consecutive failure(s)</span>
                                                ) : null}
                                                <span>Approved by {activation.approved_by}</span>
                                              </div>
                                              {activation.status === "active" ? (
                                                <div className="mt-2 flex flex-wrap justify-end gap-2">
                                                  {activation.runtime_status === "drifted" && policy ? (
                                                    <Button
                                                      type="button"
                                                      size="sm"
                                                      variant="outline"
                                                      disabled={saving === `preview:${connection.id}`}
                                                      onClick={() => void previewActivation(device, connection, policy.id)}
                                                      className="h-7 border-[#f9b115]/50 px-2 text-[11px] text-[#8b6300]"
                                                    >
                                                      Preview repair
                                                    </Button>
                                                  ) : null}
                                                  <Button
                                                    type="button"
                                                    size="sm"
                                                    variant="outline"
                                                    disabled={saving === `deactivate:${activation.id}`}
                                                    onClick={() => void deactivateCapability(device, connection, activation)}
                                                    className="h-7 border-[#e55353]/40 px-2 text-[11px] text-[#a52a2a]"
                                                  >
                                                    Deactivate
                                                  </Button>
                                                </div>
                                              ) : null}
                                            </div>
                                          );
                                        })}
                                      </div>
                                    ) : null}

                                    {connection.verification_status === "verified" ? (
                                      compatiblePolicies.length > 0 ? (
                                        <div className="mt-3 space-y-2 border-t border-[#eceef0] pt-3">
                                          <p className="text-[11px] font-semibold text-muted-foreground">Choose a published collection template</p>
                                          <div className="flex gap-2">
                                            <select
                                              aria-label="Published monitoring template"
                                              value={selectedPolicyId || ""}
                                              onChange={(event) => {
                                                setSelectedPolicies((current) => ({
                                                  ...current,
                                                  [connection.id]: event.target.value,
                                                }));
                                                setActivationPlans((current) => {
                                                  const next = { ...current };
                                                  delete next[connection.id];
                                                  return next;
                                                });
                                              }}
                                              className={cn(selectClass, "h-8 text-xs")}
                                            >
                                              {compatiblePolicies.map((policy) => (
                                                <option key={policy.id} value={policy.id}>
                                                  {policy.name} v{policy.version}
                                                </option>
                                              ))}
                                            </select>
                                            <Button
                                              type="button"
                                              size="sm"
                                              variant="outline"
                                              disabled={saving === `preview:${connection.id}` || !canActivate}
                                              onClick={() =>
                                                void previewActivation(
                                                  device,
                                                  connection,
                                                  selectedPolicyId,
                                                )
                                              }
                                              className="h-8 shrink-0 border-[#5856d6]/40 px-3 text-[11px] text-[#4947ad]"
                                            >
                                              Preview template assignment
                                            </Button>
                                          </div>

                                          {activationPlan ? (
                                            <div className="rounded-md border border-[#5856d6]/20 bg-[#e9e8fb]/30 p-2.5">
                                              <div className="flex flex-wrap items-start justify-between gap-2">
                                                <div>
                                                  <p className="text-xs font-semibold">{activationPlan.policy_name} v{activationPlan.policy_version}</p>
                                                  <p className="mt-0.5 text-[11px] text-muted-foreground">
                                                    {activationPlan.execution_mode === "scheduled"
                                                      ? `Every ${activationPlan.schedule_seconds} seconds`
                                                      : "On demand only"}
                                                    {` · ${activationPlan.artifact_name} v${activationPlan.artifact_version}`}
                                                  </p>
                                                  <p className="mt-0.5 text-[11px] text-muted-foreground">
                                                    Bound to device identity #{activationPlan.scope_device_identity_revision}. An address or site correction requires a new preview.
                                                  </p>
                                                </div>
                                                <Button
                                                  type="button"
                                                  size="sm"
                                                  disabled={saving === `approve:${connection.id}` || !canActivate}
                                                  onClick={() => void approveActivation(device, connection)}
                                                  className="h-7 bg-[#5856d6] px-3 text-[11px] hover:bg-[#4947ad]"
                                                >
                                                  Apply approved template
                                                </Button>
                                              </div>
                                              <dl className="mt-2 grid gap-1 text-[11px] sm:grid-cols-2">
                                                <div>
                                                  <dt className="font-medium text-[#4f5d73]">Target</dt>
                                                  <dd className="break-all font-mono text-muted-foreground">{JSON.stringify(activationPlan.target)}</dd>
                                                </div>
                                                <div>
                                                  <dt className="font-medium text-[#4f5d73]">Worker scope</dt>
                                                  <dd className="break-all font-mono text-muted-foreground">{JSON.stringify(activationPlan.worker_selector)}</dd>
                                                </div>
                                              </dl>
                                              {activationPlan.warnings.map((warning) => (
                                                <p key={warning} className="mt-2 rounded bg-[#f9b115]/10 px-2 py-1.5 text-[11px] text-[#8b6300]">
                                                  {warning}
                                                </p>
                                              ))}
                                              <p className="mt-2 truncate font-mono text-[9px] text-muted-foreground" title={activationPlan.plan_hash}>
                                                Plan {activationPlan.plan_hash}
                                              </p>
                                            </div>
                                          ) : null}
                                        </div>
                                      ) : (
                                        <p className="mt-2 text-xs text-muted-foreground">
                                          No published activation policy supports this protocol yet. <Link href="/assets/activation-policies" className="text-[#5856d6] underline">Create one</Link>.
                                        </p>
                                      )
                                    ) : (
                                      <p className="mt-2 text-xs text-muted-foreground">
                                        Verify the connection before creating a collection deployment.
                                      </p>
                                    )}
                                  </div> : null}
                                </div>
                              );
                            })}
                          </div> : null}
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
            {!loading && devices.length === 0 ? (
              <div className="px-5 py-12 text-center">
                <Server className="mx-auto size-8 text-muted-foreground" />
                <p className="mt-3 text-sm text-muted-foreground">No devices match this view.</p>
              </div>
            ) : null}
            {loading ? (
              <p className="px-5 py-6 text-sm text-muted-foreground">Loading devices…</p>
            ) : null}
            {!loading && devices.length > 0 ? (
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[#e4e6e9] px-5 py-4">
                <p className="text-xs text-muted-foreground">
                  Showing {devices.length} device{devices.length === 1 ? "" : "s"} on this page
                  {nextCursor ? " · more available" : " · end of results"}
                </p>
                <div className="flex gap-2">
                {previousCursors.length ? <Button variant="outline" disabled={loadingMore || loading} onClick={() => void previousPage()}>Previous page</Button> : null}
                {nextCursor ? (
                  <Button
                    type="button"
                    variant="outline"
                    disabled={loadingMore}
                    onClick={() => void loadMoreDevices()}
                  >
                    {loadingMore ? "Loading…" : "Next page"}
                  </Button>
                ) : null}
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>
        </>}
      </main>
    </div>
  );
}
