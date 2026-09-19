"use client";

import Link from "next/link";
import {
  FormEvent,
  Fragment,
  useCallback,
  useEffect,
  useMemo,
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

type Protocol =
  | "snmp"
  | "https_api"
  | "ssh"
  | "windows_exporter"
  | "winrm_https"
  | "icmp";

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
  verification_status: string;
  last_verified_at: string | null;
  last_verification_error: string | null;
  last_verification_worker_id: string | null;
  last_verification_latency_ms: number | null;
  last_verification_evidence: Record<string, unknown>;
  verification_lease_expires_at: string | null;
  activation: ConnectionActivation | null;
};

type Device = {
  id: string;
  name: string;
  kind: string;
  management_ip: string;
  vendor: string | null;
  model: string | null;
  site: string | null;
  labels: Record<string, string>;
  onboarding_status: string;
  enabled: boolean;
  connections: DeviceConnection[];
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

const apiUrl =
  process.env.NEXT_PUBLIC_ICHECK_API_URL || "http://localhost:8000/api/v1";

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

const deviceKinds = [
  ["firewall", "Firewall"],
  ["switch", "Switch"],
  ["router", "Router"],
  ["linux_server", "Linux server"],
  ["windows_server", "Windows server"],
  ["wireless_controller", "Wireless controller"],
  ["load_balancer", "Load balancer"],
  ["storage", "Storage"],
  ["hypervisor", "Hypervisor"],
  ["other", "Other"],
];

const inputClass =
  "h-10 border-[#b1b7c1] bg-white text-sm shadow-none focus-visible:border-[#5856d6] focus-visible:ring-[#5856d6]/15";
const selectClass =
  "h-10 w-full rounded-md border border-[#b1b7c1] bg-white px-3 text-sm text-[#2c384a] outline-none focus:border-[#5856d6] focus:ring-2 focus:ring-[#5856d6]/15";

async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`, init);
  if (!response.ok) {
    const document = (await response.json().catch(() => null)) as {
      detail?: string | Array<{ msg?: string }>;
    } | null;
    const detail = Array.isArray(document?.detail)
      ? document.detail.map((item) => item.msg || "Validation failed").join("; ")
      : document?.detail;
    throw new Error(detail || `Request failed with HTTP ${response.status}`);
  }
  return (await response.json()) as T;
}

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

function statusClass(status: string) {
  if (["verified", "active", "monitoring_configured"].includes(status)) {
    return "border-[#2eb85c]/30 bg-[#2eb85c]/10 text-[#1b874b]";
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

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [credentials, setCredentials] = useState<CredentialProfile[]>([]);
  const [activationPolicies, setActivationPolicies] = useState<ActivationPolicy[]>([]);
  const [selectedPolicies, setSelectedPolicies] = useState<Record<string, string>>({});
  const [activationPlans, setActivationPlans] = useState<Record<string, ActivationPlan>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [expandedDeviceId, setExpandedDeviceId] = useState<string | null>(null);
  const [message, setMessage] = useState<{
    tone: "success" | "error";
    text: string;
  } | null>(null);

  const [name, setName] = useState("");
  const [managementIp, setManagementIp] = useState("");
  const [kind, setKind] = useState("switch");
  const [site, setSite] = useState("LAB");
  const [vendor, setVendor] = useState("");
  const [model, setModel] = useState("");
  const [labels, setLabels] = useState("environment=lab");
  const [selectedProtocols, setSelectedProtocols] = useState<Protocol[]>([
    "snmp",
    "icmp",
  ]);
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
    "ssh",
  ]);

  const load = useCallback(async () => {
    try {
      const [deviceData, credentialData, policyData] = await Promise.all([
        apiRequest<Device[]>("/assets/devices"),
        apiRequest<CredentialProfile[]>("/credential-profiles"),
        apiRequest<ActivationPolicy[]>(
          "/assets/activation-policies?policy_status=published",
        ),
      ]);
      setDevices(deviceData);
      setCredentials(credentialData.filter((item) => item.enabled));
      setActivationPolicies(policyData);
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to load assets",
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timeoutId);
  }, [load]);

  const filteredDevices = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return devices;
    return devices.filter((device) =>
      [
        device.name,
        device.management_ip,
        device.kind,
        device.site,
        device.vendor,
        device.model,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [devices, search]);

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
      await apiRequest<CredentialProfile>("/credential-profiles", {
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
      setCredentialName("");
      setMessage({ tone: "success", text: "Credential reference created." });
      await load();
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
    setSaving("device");
    setMessage(null);
    try {
      const connections = selectedProtocols.map((protocol) => ({
        protocol,
        port: ports[protocol] ? Number(ports[protocol]) : null,
        credential_profile_ref: connectionCredentials[protocol] || null,
        worker_selector: { site },
        configuration: {},
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
          site,
          labels: parseLabels(labels),
          connections,
          created_by: "assets.operator",
        }),
      });
      setName("");
      setManagementIp("");
      setVendor("");
      setModel("");
      setMessage({
        tone: "success",
        text: "Device enrolled and queued for collector verification.",
      });
      await load();
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to onboard device",
      });
    } finally {
      setSaving(null);
    }
  }

  async function retryConnection(device: Device, connection: DeviceConnection) {
    const reason = window.prompt(
      `Why should ${device.name} ${connection.protocol.replaceAll("_", " ")} be verified again?`,
    );
    if (!reason?.trim()) return;
    setSaving(`retry:${connection.id}`);
    setMessage(null);
    try {
      await apiRequest<Device>(
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
      setMessage({
        tone: "success",
        text: `${device.name} ${connection.protocol.replaceAll("_", " ")} queued for verification.`,
      });
      await load();
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
    const policyId = selectedPolicies[connection.id] || fallbackPolicyId;
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
      await load();
    } catch (error) {
      setMessage({
        tone: "error",
        text: error instanceof Error ? error.message : "Unable to approve activation",
      });
    } finally {
      setSaving(null);
    }
  }

  async function deactivateConnection(device: Device, connection: DeviceConnection) {
    const reason = window.prompt(
      `Why should monitoring be deactivated for ${device.name} ${connection.protocol.replaceAll("_", " ")}?`,
    );
    if (!reason?.trim()) return;
    setSaving(`deactivate:${connection.id}`);
    setMessage(null);
    try {
      await apiRequest(
        `/assets/devices/${device.id}/connections/${connection.id}/activation/deactivate`,
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
        text: `${device.name} monitoring deployment deactivated.`,
      });
      await load();
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
      <header className="border-b border-[#d8dbe0] bg-[#303c54] text-white">
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
            <p className="text-xs text-[#a7b0bf]">Device enrollment and collection intent</p>
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
              Assets and device onboarding
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-[#768192]">
              Add lab and production devices through the control plane. Connectivity
              remains pending until a site-scoped collector verifies each monitoring
              method.
            </p>
          </div>
          <Button
            variant="outline"
            disabled={loading}
            onClick={() => {
              setLoading(true);
              void load();
            }}
            className="border-[#b1b7c1] bg-white text-[#4f5d73]"
          >
            <RefreshCw className={cn("size-4", loading && "animate-spin")} /> Refresh
          </Button>
        </div>

        {message ? (
          <div
            className={cn(
              "mb-5 flex items-center gap-2 rounded-md border px-4 py-3 text-sm",
              message.tone === "success"
                ? "border-[#2eb85c]/30 bg-[#2eb85c]/10 text-[#1b874b]"
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

        <div className="grid gap-5 xl:grid-cols-[minmax(620px,1.4fr)_minmax(380px,0.8fr)]">
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
                    <FieldLabel>Site</FieldLabel>
                    <Input required value={site} onChange={(event) => setSite(event.target.value)} placeholder="LAB" className={inputClass} />
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

                <div className="border-t border-[#e4e6e9] pt-5">
                  <div className="mb-3">
                    <h2 className="text-sm font-semibold">Monitoring methods</h2>
                    <p className="mt-1 text-xs text-[#768192]">
                      Credentials are references only. No community, password, or token is stored here.
                    </p>
                  </div>
                  <div className="grid gap-3 md:grid-cols-2">
                    {protocolOptions.map((protocol) => {
                      const selected = selectedProtocols.includes(protocol.value);
                      const compatibleCredentials = credentials.filter((credential) =>
                        credential.allowed_adapters.includes(protocol.adapter),
                      );
                      return (
                        <div key={protocol.value} className={cn("rounded-md border p-3", selected ? "border-[#5856d6]/40 bg-[#e9e8fb]/40" : "border-[#d8dbe0]")}>
                          <label className="flex cursor-pointer items-start gap-3">
                            <input type="checkbox" checked={selected} onChange={() => toggleProtocol(protocol.value)} className="mt-1 size-4 accent-[#5856d6]" />
                            <span>
                              <span className="block text-sm font-medium">{protocol.label}</span>
                              <span className="mt-0.5 block text-xs text-[#768192]">{protocol.description}</span>
                            </span>
                          </label>
                          {selected ? (
                            <div className="mt-3 grid grid-cols-[90px_1fr] gap-2">
                              <Input aria-label={`${protocol.label} port`} disabled={protocol.value === "icmp"} value={ports[protocol.value]} onChange={(event) => setPorts((current) => ({ ...current, [protocol.value]: event.target.value }))} placeholder="Port" className={cn(inputClass, "font-mono text-xs")} />
                              <select aria-label={`${protocol.label} credential`} value={connectionCredentials[protocol.value] || ""} onChange={(event) => setConnectionCredentials((current) => ({ ...current, [protocol.value]: event.target.value }))} className={selectClass}>
                                <option value="">No credential profile</option>
                                {compatibleCredentials.map((credential) => <option key={credential.id} value={credential.name}>{credential.name}</option>)}
                              </select>
                            </div>
                          ) : null}
                        </div>
                      );
                    })}
                  </div>
                </div>

                <Button disabled={saving === "device"}>
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
                    {protocolOptions.filter((item) => item.adapter !== "icmp").map((item) => (
                      <label key={item.adapter} className="flex items-center gap-2 rounded-md bg-[#f8f9fa] px-2.5 py-2 text-xs">
                        <input type="checkbox" checked={allowedAdapters.includes(item.adapter)} onChange={() => toggleAdapter(item.adapter)} className="accent-[#5856d6]" />
                        {item.label}
                      </label>
                    ))}
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
                      <p className="truncate font-mono text-[11px] text-[#768192]">{credential.secret_ref}</p>
                    </div>
                  </div>
                ))}
                {credentials.length === 0 ? <p className="text-sm text-[#8a93a2]">No credential references available.</p> : null}
              </div>
            </CardContent>
          </Card>
        </div>

        <Card className="mt-5 gap-0 border-[#d8dbe0] bg-white py-0 shadow-sm">
          <CardHeader className="border-b border-[#e4e6e9] px-5 py-4">
            <div>
              <CardTitle className="text-base">Device inventory</CardTitle>
              <CardDescription className="mt-1">Enrollment and collector-verification state</CardDescription>
            </div>
            <div className="relative mt-3 w-full max-w-sm">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[#8a93a2]" />
              <Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search device, IP, site, or vendor" className={cn(inputClass, "pl-9")} />
            </div>
          </CardHeader>
          <CardContent className="px-0">
            <Table>
              <TableHeader>
                <TableRow className="bg-[#f8f9fa] hover:bg-[#f8f9fa]">
                  <TableHead className="pl-5">Device</TableHead>
                  <TableHead>Type / site</TableHead>
                  <TableHead>Monitoring</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredDevices.map((device) => (
                  <Fragment key={device.id}>
                    <TableRow>
                      <TableCell className="pl-5">
                        <p className="text-sm font-medium">{device.name}</p>
                        <p className="mt-0.5 font-mono text-xs text-[#768192]">{device.management_ip}</p>
                      </TableCell>
                      <TableCell>
                        <p className="text-sm capitalize">{device.kind.replaceAll("_", " ")}</p>
                        <p className="mt-0.5 text-xs text-[#8a93a2]">{device.site || "No site"}</p>
                      </TableCell>
                      <TableCell>
                        <div className="flex max-w-md flex-wrap gap-1">
                          {device.connections.map((connection) => (
                            <Badge key={connection.id} variant="outline" className={cn("text-[10px]", statusClass(connection.verification_status))}>
                              {connection.protocol.replaceAll("_", " ")}
                              {connection.port ? `:${connection.port}` : ""}
                              {` · ${connection.verification_status}`}
                            </Badge>
                          ))}
                          {device.connections.length === 0 ? <span className="text-xs text-[#8a93a2]">No monitoring intent</span> : null}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge className={statusClass(device.onboarding_status)}>
                            {device.onboarding_status.replaceAll("_", " ")}
                          </Badge>
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            className="h-7 border-[#c9cdd4] px-2 text-[11px]"
                            onClick={() => setExpandedDeviceId((current) => current === device.id ? null : device.id)}
                          >
                            {expandedDeviceId === device.id ? "Hide" : "Manage"}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                    {expandedDeviceId === device.id ? (
                      <TableRow className="bg-[#f8f9fa]/70 hover:bg-[#f8f9fa]/70">
                        <TableCell colSpan={4} className="px-5 py-4">
                          <div className="grid gap-3 lg:grid-cols-2">
                            {device.connections.map((connection) => {
                              const hasEvidence = Object.keys(connection.last_verification_evidence).length > 0;
                              const retryable = ["failed", "verified"].includes(connection.verification_status);
                              const compatiblePolicies = activationPolicies.filter(
                                (policy) =>
                                  policy.protocol === connection.protocol &&
                                  policy.adapter_type === connection.adapter_type,
                              );
                              const selectedPolicyId =
                                selectedPolicies[connection.id] || compatiblePolicies[0]?.id;
                              const activationPlan = activationPlans[connection.id];
                              const activationPolicy = activationPolicies.find(
                                (policy) => policy.id === connection.activation?.policy_id,
                              );
                              const activationActive = connection.activation?.status === "active";
                              return (
                                <div key={connection.id} className="rounded-md border border-[#d8dbe0] bg-white p-3">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <p className="text-sm font-semibold capitalize">{connection.protocol.replaceAll("_", " ")}</p>
                                    <Badge className={cn("text-[10px]", statusClass(connection.verification_status))}>{connection.verification_status}</Badge>
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
                                  <p className="mt-1 text-xs text-[#768192]">
                                    {connection.adapter_type}{connection.port ? ` on port ${connection.port}` : ""}
                                  </p>
                                  {connection.last_verification_error ? (
                                    <p className="mt-2 rounded bg-[#e55353]/8 px-2 py-1.5 text-xs text-[#a52a2a]">{connection.last_verification_error}</p>
                                  ) : null}
                                  {connection.last_verified_at ? (
                                    <div className="mt-3 border-t border-[#eceef0] pt-2">
                                      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-[#768192]">
                                        {connection.last_verification_worker_id ? <span>Worker {connection.last_verification_worker_id.slice(0, 8)}</span> : null}
                                        <span>{new Date(connection.last_verified_at).toLocaleString()}</span>
                                        {connection.last_verification_latency_ms !== null ? <span>{connection.last_verification_latency_ms} ms</span> : null}
                                      </div>
                                      {hasEvidence ? (
                                        <pre className="mt-2 max-h-28 overflow-auto rounded bg-[#f3f4f7] p-2 font-mono text-[11px] text-[#4f5d73]">{JSON.stringify(connection.last_verification_evidence, null, 2)}</pre>
                                      ) : (
                                        <p className="mt-2 text-xs text-[#8a93a2]">No evidence reported yet.</p>
                                      )}
                                    </div>
                                  ) : (
                                    <p className="mt-3 text-xs text-[#8a93a2]">Waiting for a matching site worker to claim this preflight.</p>
                                  )}

                                  <div className="mt-3 border-t border-[#eceef0] pt-3">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <p className="text-xs font-semibold text-[#4f5d73]">Collection activation</p>
                                      {connection.activation ? (
                                        <Badge className={cn("text-[10px]", statusClass(connection.activation.status))}>
                                          {connection.activation.status}
                                        </Badge>
                                      ) : null}
                                    </div>

                                    {activationActive ? (
                                      <div className="mt-2 rounded-md border border-[#2eb85c]/20 bg-[#2eb85c]/5 p-2.5">
                                        <div className="flex flex-wrap items-center gap-2">
                                          <p className="text-xs font-medium text-[#1b874b]">
                                            {activationPolicy
                                              ? `${activationPolicy.name} v${activationPolicy.version}`
                                              : "Pinned activation policy"}
                                          </p>
                                          <Badge className={cn("text-[10px]", statusClass(connection.activation?.runtime_status || "pending"))}>
                                            {(connection.activation?.runtime_status || "pending").replaceAll("_", " ")}
                                          </Badge>
                                        </div>
                                        <p className="mt-1 font-mono text-[10px] text-[#657284]">
                                          Deployment {connection.activation?.deployment_id?.slice(0, 12) || "unavailable"}
                                        </p>
                                        {connection.activation?.health_reason ? (
                                          <p className="mt-1.5 text-[11px] text-[#657284]">
                                            {connection.activation.health_reason}
                                          </p>
                                        ) : null}
                                        <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-[#768192]">
                                          {connection.activation?.last_success_at ? (
                                            <span>Last success {new Date(connection.activation.last_success_at).toLocaleString()}</span>
                                          ) : null}
                                          {connection.activation?.last_failure_at ? (
                                            <span>Last failure {new Date(connection.activation.last_failure_at).toLocaleString()}</span>
                                          ) : null}
                                          {connection.activation?.consecutive_failures ? (
                                            <span>{connection.activation.consecutive_failures} consecutive failure(s)</span>
                                          ) : null}
                                        </div>
                                        <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-[#657284]">
                                          <span>Approved by {connection.activation?.approved_by}</span>
                                          <span>{new Date(connection.activation?.activated_at || "").toLocaleString()}</span>
                                          {connection.activation?.runtime_status === "drifted" && activationPolicy ? (
                                            <Button
                                              type="button"
                                              size="sm"
                                              variant="outline"
                                              disabled={saving === `preview:${connection.id}`}
                                              onClick={() => void previewActivation(device, connection, activationPolicy.id)}
                                              className="ml-auto h-7 border-[#f9b115]/50 px-2 text-[11px] text-[#8b6300]"
                                            >
                                              Preview repair
                                            </Button>
                                          ) : null}
                                          <Button
                                            type="button"
                                            size="sm"
                                            variant="outline"
                                            disabled={saving === `deactivate:${connection.id}`}
                                            onClick={() => void deactivateConnection(device, connection)}
                                            className={cn(
                                              "h-7 border-[#e55353]/40 px-2 text-[11px] text-[#a52a2a]",
                                              connection.activation?.runtime_status !== "drifted" && "ml-auto",
                                            )}
                                          >
                                            Deactivate
                                          </Button>
                                        </div>
                                        {connection.activation?.runtime_status === "drifted" && activationPlan ? (
                                          <div className="mt-2 rounded border border-[#f9b115]/30 bg-white p-2">
                                            <p className="text-[11px] text-[#657284]">
                                              Restore target {JSON.stringify(activationPlan.target)} and worker scope {JSON.stringify(activationPlan.worker_selector)}.
                                            </p>
                                            <Button
                                              type="button"
                                              size="sm"
                                              disabled={saving === `approve:${connection.id}`}
                                              onClick={() => void approveActivation(device, connection)}
                                              className="mt-2 h-7 bg-[#5856d6] px-3 text-[11px] hover:bg-[#4947ad]"
                                            >
                                              Approve repair
                                            </Button>
                                          </div>
                                        ) : null}
                                      </div>
                                    ) : connection.verification_status === "verified" ? (
                                      compatiblePolicies.length > 0 ? (
                                        <div className="mt-2 space-y-2">
                                          <div className="flex gap-2">
                                            <select
                                              aria-label="Activation policy"
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
                                              disabled={saving === `preview:${connection.id}`}
                                              onClick={() =>
                                                void previewActivation(
                                                  device,
                                                  connection,
                                                  selectedPolicyId,
                                                )
                                              }
                                              className="h-8 shrink-0 border-[#5856d6]/40 px-3 text-[11px] text-[#4947ad]"
                                            >
                                              Preview
                                            </Button>
                                          </div>

                                          {activationPlan ? (
                                            <div className="rounded-md border border-[#5856d6]/20 bg-[#e9e8fb]/30 p-2.5">
                                              <div className="flex flex-wrap items-start justify-between gap-2">
                                                <div>
                                                  <p className="text-xs font-semibold">{activationPlan.policy_name} v{activationPlan.policy_version}</p>
                                                  <p className="mt-0.5 text-[11px] text-[#657284]">
                                                    {activationPlan.execution_mode === "scheduled"
                                                      ? `Every ${activationPlan.schedule_seconds} seconds`
                                                      : "On demand only"}
                                                    {` · ${activationPlan.artifact_name} v${activationPlan.artifact_version}`}
                                                  </p>
                                                </div>
                                                <Button
                                                  type="button"
                                                  size="sm"
                                                  disabled={saving === `approve:${connection.id}`}
                                                  onClick={() => void approveActivation(device, connection)}
                                                  className="h-7 bg-[#5856d6] px-3 text-[11px] hover:bg-[#4947ad]"
                                                >
                                                  Approve activation
                                                </Button>
                                              </div>
                                              <dl className="mt-2 grid gap-1 text-[11px] sm:grid-cols-2">
                                                <div>
                                                  <dt className="font-medium text-[#4f5d73]">Target</dt>
                                                  <dd className="break-all font-mono text-[#657284]">{JSON.stringify(activationPlan.target)}</dd>
                                                </div>
                                                <div>
                                                  <dt className="font-medium text-[#4f5d73]">Worker scope</dt>
                                                  <dd className="break-all font-mono text-[#657284]">{JSON.stringify(activationPlan.worker_selector)}</dd>
                                                </div>
                                              </dl>
                                              {activationPlan.warnings.map((warning) => (
                                                <p key={warning} className="mt-2 rounded bg-[#f9b115]/10 px-2 py-1.5 text-[11px] text-[#8b6300]">
                                                  {warning}
                                                </p>
                                              ))}
                                              <p className="mt-2 truncate font-mono text-[9px] text-[#8a93a2]" title={activationPlan.plan_hash}>
                                                Plan {activationPlan.plan_hash}
                                              </p>
                                            </div>
                                          ) : null}
                                        </div>
                                      ) : (
                                        <p className="mt-2 text-xs text-[#8a93a2]">
                                          No published activation policy supports this protocol yet.
                                        </p>
                                      )
                                    ) : (
                                      <p className="mt-2 text-xs text-[#8a93a2]">
                                        Verify the connection before creating a collection deployment.
                                      </p>
                                    )}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
            {filteredDevices.length === 0 ? (
              <div className="px-5 py-12 text-center">
                <Server className="mx-auto size-8 text-[#b1b7c1]" />
                <p className="mt-3 text-sm text-[#768192]">No devices match this view.</p>
              </div>
            ) : null}
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
