"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bell,
  Boxes,
  Cable,
  Check,
  ChevronRight,
  CircleDot,
  Command,
  Database,
  GitBranch,
  Laptop,
  LayoutDashboard,
  Menu,
  Network,
  Radio,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  Wifi,
  X,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { useAlertWebMCP } from "@/app/webmcp";

type AlertStatus = "open" | "acknowledged" | "resolved";
type Severity = "critical" | "warning" | "info";

type AlertRecord = {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  entity_id: string;
  event_type: string;
  occurrence_count: number;
  last_seen: string;
};

type EndpointRecord = {
  id: string;
  mac_address: string;
  hostname: string | null;
  username: string | null;
  vendor: string | null;
  last_seen: string;
  current_ips: Array<{ address: string; source: string; vlan_id: number | null }>;
  current_attachments: Array<{
    interface_name: string | null;
    vlan_id: number | null;
    source: string;
  }>;
  current_wireless_sessions: Array<{
    access_point: string | null;
    ssid: string | null;
    rssi: number | null;
    band: string | null;
  }>;
};

type DashboardData = {
  devices: number;
  endpoints: number;
  active_wireless_clients: number;
  open_alerts: number;
  critical_alerts: number;
  recent_alerts: AlertRecord[];
  recent_endpoints: EndpointRecord[];
};

const minutesAgo = (minutes: number) =>
  new Date(Date.now() - minutes * 60_000).toISOString();

const mockData: DashboardData = {
  devices: 128,
  endpoints: 3421,
  active_wireless_clients: 817,
  open_alerts: 12,
  critical_alerts: 2,
  recent_alerts: [
    {
      id: "ALT-4832",
      title: "Core uplink error rate rising",
      description: "CRC errors on core-hk-01 Te1/0/48 are 41× above baseline.",
      severity: "critical",
      status: "open",
      entity_id: "core-hk-01",
      event_type: "interface.errors.high",
      occurrence_count: 8,
      last_seen: minutesAgo(7),
    },
    {
      id: "ALT-4831",
      title: "Weak Wi-Fi signal",
      description: "mira-iphone is at −82 dBm on AP-HK-17F-03.",
      severity: "warning",
      status: "open",
      entity_id: "a4:83:e7:10:2f:91",
      event_type: "wireless.rssi.low",
      occurrence_count: 4,
      last_seen: minutesAgo(11),
    },
    {
      id: "ALT-4828",
      title: "Endpoint IP address changed",
      description: "ops-laptop-17 moved from 10.20.17.19 to 10.20.17.21.",
      severity: "info",
      status: "acknowledged",
      entity_id: "00:1b:44:11:3a:b7",
      event_type: "endpoint.ip.changed",
      occurrence_count: 1,
      last_seen: minutesAgo(24),
    },
  ],
  recent_endpoints: [
    {
      id: "ep-1",
      mac_address: "00:1b:44:11:3a:b7",
      hostname: "ops-laptop-17",
      username: "alex.chen",
      vendor: "Lenovo",
      last_seen: minutesAgo(2),
      current_ips: [{ address: "10.20.17.21", source: "arp", vlan_id: 120 }],
      current_attachments: [
        { interface_name: "Te1/0/18", vlan_id: 120, source: "mac_table" },
      ],
      current_wireless_sessions: [],
    },
    {
      id: "ep-2",
      mac_address: "a4:83:e7:10:2f:91",
      hostname: "mira-iphone",
      username: "mira.patel",
      vendor: "Apple",
      last_seen: minutesAgo(3),
      current_ips: [
        { address: "10.20.31.54", source: "wifi_controller", vlan_id: 131 },
      ],
      current_attachments: [],
      current_wireless_sessions: [
        { access_point: "AP-HK-17F-03", ssid: "CORP", rssi: -82, band: "5 GHz" },
      ],
    },
    {
      id: "ep-3",
      mac_address: "38:f9:d3:2b:a1:06",
      hostname: "finance-mbp-04",
      username: "sam.wong",
      vendor: "Apple",
      last_seen: minutesAgo(5),
      current_ips: [
        { address: "10.20.31.72", source: "wifi_controller", vlan_id: 131 },
      ],
      current_attachments: [],
      current_wireless_sessions: [
        { access_point: "AP-HK-18F-01", ssid: "CORP", rssi: -51, band: "6 GHz" },
      ],
    },
    {
      id: "ep-4",
      mac_address: "6c:4b:90:8d:2c:11",
      hostname: "warehouse-scanner-08",
      username: null,
      vendor: "Zebra",
      last_seen: minutesAgo(8),
      current_ips: [{ address: "10.20.40.88", source: "arp", vlan_id: 140 }],
      current_attachments: [
        { interface_name: "Te1/0/42", vlan_id: 140, source: "mac_table" },
      ],
      current_wireless_sessions: [],
    },
  ],
};

const navigation = [
  { label: "Situation", icon: LayoutDashboard, active: true },
  { label: "AI operations", icon: Sparkles },
  { label: "Topology", icon: GitBranch },
  { label: "Incidents", icon: AlertTriangle, count: 3 },
  { label: "Assets", icon: Boxes },
  { label: "Changes", icon: ShieldCheck },
  { label: "Automation", icon: Command },
];

function relativeTime(value: string): string {
  const minutes = Math.max(
    1,
    Math.round((Date.now() - new Date(value).getTime()) / 60_000),
  );
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  return hours < 24 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`;
}

function SeverityMark({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "mt-0.5 grid size-8 shrink-0 place-items-center rounded-md border",
        severity === "critical" &&
          "border-[#e55353]/30 bg-[#e55353]/10 text-[#bd2b2b]",
        severity === "warning" &&
          "border-[#f9b115]/35 bg-[#f9b115]/12 text-[#a66d03]",
        severity === "info" &&
          "border-[#3399ff]/30 bg-[#3399ff]/10 text-[#176fb3]",
      )}
    >
      {severity === "critical" ? (
        <X className="size-4" aria-hidden="true" />
      ) : severity === "warning" ? (
        <AlertTriangle className="size-4" aria-hidden="true" />
      ) : (
        <CircleDot className="size-4" aria-hidden="true" />
      )}
    </span>
  );
}

function SignalBars({ rssi }: { rssi: number | null }) {
  const level =
    rssi === null ? 0 : rssi >= -60 ? 4 : rssi >= -70 ? 3 : rssi >= -80 ? 2 : 1;
  return (
    <span
      className="flex h-5 items-end gap-[3px]"
      aria-label={rssi === null ? "No signal data" : `${rssi} dBm`}
    >
      {[1, 2, 3, 4].map((bar) => (
        <span
          key={bar}
          className={cn(
            "w-[3px] rounded-full bg-[#c4c9d0]",
            bar <= level &&
              (level <= 1
                ? "bg-[#e55353]"
                : level === 2
                  ? "bg-[#f9b115]"
                  : "bg-[#3399ff]"),
          )}
          style={{ height: `${5 + bar * 3}px` }}
        />
      ))}
    </span>
  );
}

export default function Home() {
  const [data, setData] = useState(mockData);
  const [search, setSearch] = useState("");
  const [mobileNav, setMobileNav] = useState(false);
  const [source, setSource] = useState<"demo" | "live">("demo");
  const apiUrl = process.env.NEXT_PUBLIC_ICHECK_API_URL;

  useEffect(() => {
    if (!apiUrl) return;
    const controller = new AbortController();
    fetch(`${apiUrl}/dashboard/summary`, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("API unavailable");
        return response.json() as Promise<DashboardData>;
      })
      .then((payload) => {
        setData(payload);
        setSource("live");
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [apiUrl]);

  const filteredEndpoints = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return data.recent_endpoints;
    return data.recent_endpoints.filter((endpoint) =>
      [
        endpoint.hostname,
        endpoint.username,
        endpoint.vendor,
        endpoint.mac_address,
        ...endpoint.current_ips.map((item) => item.address),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [data.recent_endpoints, search]);

  async function acknowledge(alertId: string) {
    setData((current) => ({
      ...current,
      recent_alerts: current.recent_alerts.map((alert) =>
        alert.id === alertId ? { ...alert, status: "acknowledged" } : alert,
      ),
    }));
    if (source === "live" && apiUrl) {
      await fetch(`${apiUrl}/alerts/${alertId}/acknowledge`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ actor: "dashboard.operator" }),
      }).catch(() => undefined);
    }
  }

  useAlertWebMCP(acknowledge);

  const summary = [
    {
      label: "Managed devices",
      value: data.devices.toLocaleString(),
      detail: "126 collecting",
      icon: Database,
      tone: "bg-[#5856d6]",
    },
    {
      label: "Known endpoints",
      value: data.endpoints.toLocaleString(),
      detail: "+47 this week",
      icon: Laptop,
      tone: "bg-[#3399ff]",
    },
    {
      label: "Wireless now",
      value: data.active_wireless_clients.toLocaleString(),
      detail: "4 controllers",
      icon: Wifi,
      tone: "bg-[#2eb85c]",
    },
    {
      label: "Open alerts",
      value: data.open_alerts.toLocaleString(),
      detail: `${data.critical_alerts} critical`,
      icon: Bell,
      tone: "bg-[#e55353]",
    },
    {
      label: "Coverage",
      value: "98.4%",
      detail: "Across 6 sites",
      icon: ShieldCheck,
      tone: "bg-[#f9b115]",
    },
  ];

  return (
    <div className="min-h-screen bg-[#f3f4f7] text-[#2c384a]">
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-[256px] -translate-x-full flex-col bg-[#303c54] text-white shadow-xl transition-transform lg:translate-x-0",
          mobileNav && "translate-x-0",
        )}
      >
        <div className="flex h-16 items-center justify-between bg-[#28344a] px-5 shadow-sm">
          <div className="flex items-center gap-3">
            <span className="grid size-9 place-items-center rounded-md bg-[#5856d6] text-white shadow-sm">
              <Activity className="size-[18px]" aria-hidden="true" />
            </span>
            <div>
              <p className="text-lg font-semibold tracking-[-0.02em]">iCheck</p>
              <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-[#a7b0bf]">
                Operations
              </p>
            </div>
          </div>
          <Button
            variant="ghost"
            size="icon-sm"
            className="text-[#c2c7d0] hover:bg-white/10 hover:text-white lg:hidden"
            onClick={() => setMobileNav(false)}
            aria-label="Close navigation"
          >
            <X />
          </Button>
        </div>

        <nav className="space-y-1 p-3" aria-label="Primary navigation">
          <p className="px-3 pb-2 pt-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-[#8d97a8]">
            Operations
          </p>
          {navigation.map((item) => (
            <button
              type="button"
              key={item.label}
              className={cn(
                "flex h-11 w-full items-center gap-3 rounded-md px-3 text-left text-sm font-medium text-[#c2c7d0] transition-colors hover:bg-white/[0.08] hover:text-white",
                item.active &&
                  "bg-[#46546c] text-white shadow-[inset_3px_0_0_#7a79df]",
              )}
            >
              <item.icon className="size-[17px]" aria-hidden="true" />
              <span>{item.label}</span>
              {item.count ? (
                <span className="ml-auto rounded-full bg-[#e55353] px-2 py-0.5 text-xs text-white">
                  {item.count}
                </span>
              ) : null}
            </button>
          ))}
        </nav>

        <div className="mt-auto space-y-3 border-t border-white/10 p-3">
          <div className="rounded-md border border-white/10 bg-white/[0.05] p-3.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-[#e6e9ed]">Collection health</span>
              <span className="size-2 rounded-full bg-[#2eb85c]" />
            </div>
            <div className="mt-3 grid grid-cols-3 gap-2 text-center">
              {[
                ["SNMP", "126"],
                ["WMI", "38"],
                ["WLC", "4"],
              ].map(([label, value]) => (
                <div key={label} className="rounded-sm bg-black/10 px-1 py-2">
                  <p className="text-sm font-semibold text-white">{value}</p>
                  <p className="mt-0.5 text-[10px] tracking-wide text-[#9da6b5]">{label}</p>
                </div>
              ))}
            </div>
          </div>
          <Link
            href="/settings/ai"
            className="flex h-10 w-full items-center gap-3 rounded-md px-3 text-sm font-medium text-[#c2c7d0] hover:bg-white/[0.08] hover:text-white"
          >
            <Settings className="size-[17px]" aria-hidden="true" />
            Administration
          </Link>
        </div>
      </aside>

      {mobileNav ? (
        <button
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={() => setMobileNav(false)}
          aria-label="Close navigation overlay"
        />
      ) : null}

      <main className="min-w-0 lg:pl-[256px]">
        <header className="sticky top-0 z-20 flex h-16 items-center gap-4 border-b border-[#d8dbe0] bg-white px-4 shadow-sm sm:px-6 xl:px-8">
          <Button
            variant="ghost"
            size="icon"
            className="text-[#4f5d73] hover:bg-[#ebedef] lg:hidden"
            onClick={() => setMobileNav(true)}
            aria-label="Open navigation"
          >
            <Menu />
          </Button>
          <div>
            <p className="text-base font-semibold tracking-tight text-[#2c384a]">Situation room</p>
            <p className="hidden text-xs text-[#768192] sm:block">
              Hong Kong · All production systems
            </p>
          </div>
          <div className="ml-auto flex items-center gap-2 sm:gap-3">
            <Badge
              variant="outline"
              className={cn(
                "hidden h-7 border-[#d8dbe0] bg-[#f3f4f7] px-2.5 text-[11px] font-medium sm:flex",
                source === "live" ? "text-[#1b874b]" : "text-[#5c6873]",
              )}
            >
              <span
                className={cn(
                  "size-1.5 rounded-full",
                  source === "live" ? "bg-[#2eb85c]" : "bg-[#3399ff]",
                )}
              />
              {source === "live" ? "Live API" : "Demo snapshot"}
            </Badge>
            <Button
              variant="ghost"
              size="icon"
              className="relative text-[#768192] hover:bg-[#ebedef] hover:text-[#2c384a]"
              aria-label="Notifications"
            >
              <Bell />
              <span className="absolute right-2 top-2 size-1.5 rounded-full bg-[#e55353]" />
            </Button>
            <div className="grid size-9 place-items-center rounded-full bg-[#5856d6] text-xs font-semibold text-white shadow-sm">
              ZL
            </div>
          </div>
        </header>

        <div className="mx-auto max-w-[1680px] space-y-5 px-4 py-5 sm:px-6 xl:px-8 xl:py-7">
          <section className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
            <div>
              <div className="flex items-center gap-2 text-sm text-[#768192]">
                Home <ChevronRight className="size-3" aria-hidden="true" /> Dashboard
              </div>
              <h1 className="mt-2 text-2xl font-semibold tracking-[-0.025em] text-[#2c384a] sm:text-[1.75rem]">
                Infrastructure overview
              </h1>
            </div>
            <p className="max-w-md text-sm leading-6 text-[#768192]">
              Identity, location, and alert state correlated across the network.
            </p>
          </section>

          <section
            className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5"
            aria-label="Infrastructure summary"
          >
            {summary.map((stat) => (
              <Card
                key={stat.label}
                className={cn(
                  "gap-0 overflow-hidden border-0 py-0 text-white shadow-sm",
                  stat.tone,
                )}
              >
                <CardContent className="flex items-center gap-4 px-4 py-4">
                  <span
                    className="grid size-10 place-items-center rounded-md bg-black/10 text-white"
                  >
                    <stat.icon className="size-[18px]" aria-hidden="true" />
                  </span>
                  <div className="min-w-0">
                    <p className="text-[13px] text-white/75">{stat.label}</p>
                    <div className="mt-0.5 flex items-baseline gap-2">
                      <p className="text-xl font-semibold tracking-tight text-white">
                        {stat.value}
                      </p>
                      <p
                        className={cn(
                          "truncate text-[11px] text-white/65",
                        )}
                      >
                        {stat.detail}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </section>

          <Card className="gap-0 overflow-hidden border-[#d8dbe0] bg-white py-0 shadow-sm">
            <CardHeader className="border-b border-[#d8dbe0] px-4 py-4 sm:px-5">
              <div>
                <CardTitle className="text-sm font-semibold text-[#2c384a]">
                  Service path
                </CardTitle>
                <CardDescription className="mt-1 text-xs text-[#768192]">
                  Payment traffic · Hong Kong production
                </CardDescription>
              </div>
              <CardAction>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-xs text-[#5856d6] hover:bg-[#e9e8fb] hover:text-[#3c3a9f]"
                >
                  Open topology <ChevronRight />
                </Button>
              </CardAction>
            </CardHeader>
            <CardContent className="overflow-x-auto px-4 py-4 sm:px-5">
              <div className="flex min-w-[720px] items-center">
                {[
                  { label: "Internet", meta: "2 ISPs", icon: Network, state: "ok" },
                  {
                    label: "core-hk-01",
                    meta: "CRC warning",
                    icon: Cable,
                    state: "critical",
                  },
                  {
                    label: "fw-hk-02",
                    meta: "12.4k sessions",
                    icon: ShieldCheck,
                    state: "ok",
                  },
                  {
                    label: "leaf-hk-17",
                    meta: "63% utilization",
                    icon: GitBranch,
                    state: "ok",
                  },
                  {
                    label: "payment-api",
                    meta: "18 pods healthy",
                    icon: Boxes,
                    state: "ok",
                  },
                ].map((node, index, nodes) => (
                  <div key={node.label} className="flex flex-1 items-center">
                    <div className="flex min-w-[112px] items-center gap-3">
                      <span
                        className={cn(
                          "relative grid size-9 shrink-0 place-items-center rounded-md border border-[#2eb85c]/25 bg-[#2eb85c]/10 text-[#1b874b]",
                          node.state === "critical" &&
                            "border-[#e55353]/30 bg-[#e55353]/10 text-[#bd2b2b]",
                        )}
                      >
                        <node.icon className="size-4" aria-hidden="true" />
                        <span
                          className={cn(
                            "absolute -right-1 -top-1 size-2.5 rounded-full border-2 border-white bg-[#2eb85c]",
                            node.state === "critical" && "bg-[#e55353]",
                          )}
                        />
                      </span>
                      <div>
                        <p className="text-xs font-semibold text-[#3c4b64]">
                          {node.label}
                        </p>
                        <p
                          className={cn(
                            "mt-0.5 text-[10px] text-[#768192]",
                            node.state === "critical" && "text-[#bd2b2b]",
                          )}
                        >
                          {node.meta}
                        </p>
                      </div>
                    </div>
                    {index < nodes.length - 1 ? (
                      <div className="mx-3 h-px min-w-6 flex-1 bg-gradient-to-r from-[#5856d6]/50 to-[#5856d6]/10" />
                    ) : null}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <section className="grid min-w-0 gap-5 xl:grid-cols-[minmax(350px,0.9fr)_minmax(620px,1.55fr)]">
            <Card className="min-w-0 gap-0 border-[#d8dbe0] bg-white py-0 shadow-sm">
              <Tabs defaultValue="active" className="gap-0">
                <CardHeader className="border-b border-[#d8dbe0] px-4 py-4 sm:px-5">
                  <div>
                    <CardTitle className="flex items-center gap-2 text-sm font-semibold text-[#2c384a]">
                      Alert center
                      <Badge className="border-[#e55353]/25 bg-[#e55353]/10 text-[#bd2b2b]">
                        {data.open_alerts}
                      </Badge>
                    </CardTitle>
                    <CardDescription className="mt-1 text-xs text-[#768192]">
                      Correlated conditions requiring attention
                    </CardDescription>
                  </div>
                  <CardAction>
                    <TabsList variant="line" className="h-8 text-xs">
                      <TabsTrigger value="active" className="px-2 text-xs">
                        Active
                      </TabsTrigger>
                      <TabsTrigger value="all" className="px-2 text-xs">
                        All
                      </TabsTrigger>
                    </TabsList>
                  </CardAction>
                </CardHeader>
                {["active", "all"].map((tab) => (
                  <TabsContent key={tab} value={tab}>
                    <CardContent className="divide-y divide-[#d8dbe0] px-0">
                      {data.recent_alerts
                        .filter(
                          (alert) => tab === "all" || alert.status !== "resolved",
                        )
                        .map((alert) => (
                          <article
                            key={alert.id}
                            className="flex gap-3 px-4 py-4 transition-colors hover:bg-[#f8f9fa] sm:px-5"
                          >
                            <SeverityMark severity={alert.severity} />
                            <div className="min-w-0 flex-1">
                              <div className="flex items-start justify-between gap-3">
                                <div>
                                  <h2 className="text-sm font-semibold leading-5 text-[#3c4b64]">
                                    {alert.title}
                                  </h2>
                                  <p className="mt-1 text-xs leading-5 text-[#768192]">
                                    {alert.description}
                                  </p>
                                </div>
                                <span className="whitespace-nowrap text-xs text-[#8a93a2]">
                                  {relativeTime(alert.last_seen)}
                                </span>
                              </div>
                              <div className="mt-3 flex flex-wrap items-center gap-2">
                                <Badge
                                  variant="outline"
                                  className="border-[#d8dbe0] bg-[#f8f9fa] font-mono text-xs text-[#5c6873]"
                                >
                                  {alert.entity_id}
                                </Badge>
                                <span className="text-xs text-[#8a93a2]">
                                  ×{alert.occurrence_count}
                                </span>
                                {alert.status === "open" ? (
                                  <Button
                                    variant="ghost"
                                    size="xs"
                                    className="ml-auto text-[#5856d6] hover:bg-[#e9e8fb] hover:text-[#3c3a9f]"
                                    onClick={() => acknowledge(alert.id)}
                                  >
                                    <Check /> Acknowledge
                                  </Button>
                                ) : (
                                  <span className="ml-auto flex items-center gap-1 text-xs capitalize text-[#1b874b]">
                                    <Check className="size-3" /> {alert.status}
                                  </span>
                                )}
                              </div>
                            </div>
                          </article>
                        ))}
                    </CardContent>
                  </TabsContent>
                ))}
              </Tabs>
            </Card>

            <Card className="min-w-0 gap-0 border-[#d8dbe0] bg-white py-0 shadow-sm">
              <Tabs defaultValue="all" className="gap-0">
                <CardHeader className="border-b border-[#d8dbe0] px-4 py-4 sm:px-5">
                  <div>
                    <CardTitle className="text-sm font-semibold text-[#2c384a]">
                      Endpoint identity
                    </CardTitle>
                    <CardDescription className="mt-1 text-xs text-[#768192]">
                      Current IP, MAC, attachment, and Wi-Fi association
                    </CardDescription>
                  </div>
                  <CardAction>
                    <TabsList variant="line" className="hidden h-8 sm:flex">
                      <TabsTrigger value="all" className="px-2 text-xs">
                        All
                      </TabsTrigger>
                      <TabsTrigger value="wireless" className="px-2 text-xs">
                        Wireless
                      </TabsTrigger>
                    </TabsList>
                  </CardAction>
                </CardHeader>
                <div className="flex items-center border-b border-[#d8dbe0] bg-[#f8f9fa] px-4 py-3 sm:px-5">
                  <div className="relative w-full max-w-sm">
                    <Search
                      className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[#8a93a2]"
                      aria-hidden="true"
                    />
                    <Input
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                      placeholder="Search IP, MAC, host, or user"
                      aria-label="Search endpoints"
                      className="h-9 border-[#b1b7c1] bg-white pl-9 text-sm text-[#2c384a] shadow-none placeholder:text-[#8a93a2] focus-visible:border-[#5856d6] focus-visible:ring-[#5856d6]/15"
                    />
                  </div>
                  <span className="ml-auto hidden text-xs text-[#8a93a2] sm:block">
                    Updated 12s ago
                  </span>
                </div>
                {[
                  { value: "all", wirelessOnly: false },
                  { value: "wireless", wirelessOnly: true },
                ].map(({ value, wirelessOnly }) => (
                  <TabsContent key={value} value={value}>
                    <CardContent className="px-0">
                      <Table>
                        <TableHeader>
                          <TableRow className="border-[#d8dbe0] bg-[#f8f9fa] hover:bg-[#f8f9fa]">
                            <TableHead className="h-10 pl-5 text-xs font-semibold uppercase tracking-[0.06em] text-[#5c6873]">
                              Identity
                            </TableHead>
                            <TableHead className="h-10 text-xs font-semibold uppercase tracking-[0.06em] text-[#5c6873]">
                              IP / VLAN
                            </TableHead>
                            <TableHead className="h-10 text-xs font-semibold uppercase tracking-[0.06em] text-[#5c6873]">
                              Attached to
                            </TableHead>
                            <TableHead className="h-10 text-xs font-semibold uppercase tracking-[0.06em] text-[#5c6873]">
                              Signal
                            </TableHead>
                            <TableHead className="h-10 pr-5 text-right text-xs font-semibold uppercase tracking-[0.06em] text-[#5c6873]">
                              Seen
                            </TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {filteredEndpoints
                            .filter(
                              (endpoint) =>
                                !wirelessOnly ||
                                endpoint.current_wireless_sessions.length > 0,
                            )
                            .map((endpoint) => {
                              const ip = endpoint.current_ips[0];
                              const wireless = endpoint.current_wireless_sessions[0];
                              const attachment = endpoint.current_attachments[0];
                              return (
                                <TableRow
                                  key={endpoint.id}
                                  className="border-[#d8dbe0] hover:bg-[#f8f9fa]"
                                >
                                  <TableCell className="py-3 pl-5">
                                    <div className="flex items-center gap-2.5">
                                      <span className="grid size-8 place-items-center rounded-md bg-[#ebedef] text-[#5c6873]">
                                        {wireless ? (
                                          <Radio className="size-4" />
                                        ) : (
                                          <Laptop className="size-4" />
                                        )}
                                      </span>
                                      <div>
                                        <p className="text-sm font-medium text-[#3c4b64]">
                                          {endpoint.hostname || "Unknown endpoint"}
                                        </p>
                                        <p className="mt-0.5 font-mono text-xs text-[#8a93a2]">
                                          {endpoint.mac_address}
                                        </p>
                                      </div>
                                    </div>
                                  </TableCell>
                                  <TableCell className="py-3">
                                    <p className="font-mono text-sm text-[#3c4b64]">
                                      {ip?.address || "—"}
                                    </p>
                                    <p className="mt-0.5 text-xs text-[#8a93a2]">
                                      VLAN {ip?.vlan_id || "—"}
                                    </p>
                                  </TableCell>
                                  <TableCell className="py-3">
                                    <p className="text-sm text-[#3c4b64]">
                                      {wireless?.access_point ||
                                        attachment?.interface_name ||
                                        "Unknown"}
                                    </p>
                                    <p className="mt-0.5 text-xs text-[#8a93a2]">
                                      {wireless?.ssid ||
                                        attachment?.source ||
                                        ip?.source ||
                                        "—"}
                                    </p>
                                  </TableCell>
                                  <TableCell className="py-3">
                                    {wireless ? (
                                      <div className="flex items-center gap-2">
                                        <SignalBars rssi={wireless.rssi} />
                                        <span
                                          className={cn(
                                            "text-xs text-[#768192]",
                                            wireless.rssi !== null &&
                                              wireless.rssi < -75 &&
                                              "text-[#a66d03]",
                                          )}
                                        >
                                          {wireless.rssi} dBm
                                        </span>
                                      </div>
                                    ) : (
                                      <span className="text-xs text-[#8a93a2]">
                                        Wired
                                      </span>
                                    )}
                                  </TableCell>
                                  <TableCell className="py-3 pr-5 text-right text-xs text-[#768192]">
                                    {relativeTime(endpoint.last_seen)}
                                  </TableCell>
                                </TableRow>
                              );
                            })}
                        </TableBody>
                      </Table>
                      {filteredEndpoints.length === 0 ? (
                        <div className="px-5 py-10 text-center text-sm text-[#768192]">
                          No endpoint matches “{search}”.
                        </div>
                      ) : null}
                    </CardContent>
                  </TabsContent>
                ))}
              </Tabs>
            </Card>
          </section>
        </div>
        <footer className="flex flex-col gap-1 border-t border-[#d8dbe0] bg-white px-4 py-3 text-xs text-[#768192] sm:flex-row sm:items-center sm:justify-between sm:px-6 xl:px-8">
          <p>
            <span className="font-medium text-[#5856d6]">iCheck</span> infrastructure operations
          </p>
          <p>Hong Kong production · monitored continuously</p>
        </footer>
      </main>
    </div>
  );
}
