"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowLeft,
  Bot,
  Boxes,
  CircleDot,
  GitBranch,
  Layers3,
  LockKeyhole,
  Network,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  Wrench,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiFetch as apiRequest } from "@/lib/icheck-api";
import { topologyEdgePaths } from "@/lib/topology-edge-paths";
import { cn } from "@/lib/utils";

type NodeType = "device" | "endpoint" | "knowledge_entity";
type EdgeType =
  | "wired_attachment"
  | "wireless_association"
  | "ip_observation"
  | "knowledge_relationship";
type Layout = "force" | "hierarchical" | "radial";

type TopologyView = {
  artifact_id: string;
  name: string;
  description: string;
  version_id: string;
  version: number;
  published_at: string;
  content_hash: string;
  layout: Layout;
  group_by: "none" | "site" | "kind";
  node_types: NodeType[];
  edge_types: EdgeType[];
  max_nodes: number;
  max_edges: number;
};

type TopologyNode = {
  id: string;
  entity_id: string;
  node_type: NodeType;
  label: string;
  kind: string;
  site: string | null;
  group: string | null;
  status: string;
  mac_address: string | null;
  external_key: string | null;
};

type TopologyEdge = {
  id: string;
  edge_type: EdgeType;
  relationship_type: string | null;
  source: string;
  target: string;
  label: string;
  metadata: Record<string, unknown>;
};

type TopologyRender = TopologyView & {
  rendered_at: string;
  scope_applied: boolean;
  spec: {
    artifact_name: string;
    description: string;
    sites: string[];
    device_kinds: string[];
    knowledge_entity_types: string[];
    knowledge_relationship_types: string[];
  };
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  node_count: number;
  edge_count: number;
  nodes_truncated: boolean;
  edges_truncated: boolean;
  limits: { nodes: number; edges: number };
  context: {
    situation_id: string;
    title: string;
    status: string;
    severity: string;
    root_node_id: string;
    hypothesis_boundary: "deterministic_context_not_root_cause";
    native_neighbor_count: number;
    knowledge_entity_count: number;
    service_count: number;
    service_dependency_count: number;
    path_count: number;
  } | null;
};

type Point = { x: number; y: number };

const nodePalette: Record<NodeType, { fill: string; halo: string; label: string }> = {
  device: { fill: "#7c6ee6", halo: "#ded9ff", label: "Device" },
  endpoint: { fill: "#22a66f", halo: "#c9f3df", label: "Endpoint" },
  knowledge_entity: { fill: "#e39a2d", halo: "#fae6c3", label: "Knowledge entity" },
};

function relativeTime(value: string) {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function shortHash(value: string) {
  return `${value.slice(0, 10)}…${value.slice(-6)}`;
}

function positionsFor(nodes: TopologyNode[], layout: Layout): Map<string, Point> {
  const width = 1000;
  const height = 620;
  const points = new Map<string, Point>();
  if (!nodes.length) return points;

  if (layout === "radial") {
    const radius = Math.min(245, 90 + nodes.length * 9);
    nodes.forEach((node, index) => {
      const angle = (Math.PI * 2 * index) / nodes.length - Math.PI / 2;
      points.set(node.id, {
        x: width / 2 + Math.cos(angle) * radius,
        y: height / 2 + Math.sin(angle) * radius,
      });
    });
    return points;
  }

  if (layout === "hierarchical") {
    const orderedTypes: NodeType[] = ["device", "knowledge_entity", "endpoint"];
    const present = orderedTypes.filter((type) => nodes.some((node) => node.node_type === type));
    present.forEach((type, columnIndex) => {
      const column = nodes.filter((node) => node.node_type === type);
      const x = ((columnIndex + 1) * width) / (present.length + 1);
      column.forEach((node, rowIndex) => {
        points.set(node.id, {
          x,
          y: ((rowIndex + 1) * height) / (column.length + 1),
        });
      });
    });
    return points;
  }

  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  nodes.forEach((node, index) => {
    const radius = 42 + Math.sqrt(index) * 43;
    const angle = index * goldenAngle;
    points.set(node.id, {
      x: width / 2 + Math.cos(angle) * radius,
      y: height / 2 + Math.sin(angle) * radius * 0.82,
    });
  });
  return points;
}

function edgeStroke(edge: TopologyEdge) {
  if (edge.edge_type === "knowledge_relationship") return "#cc8a2a";
  if (edge.edge_type === "wireless_association") return "#5d8fd7";
  if (edge.edge_type === "ip_observation") return "#8693a8";
  return "#687991";
}

export default function TopologyOperatorPage() {
  const [views, setViews] = useState<TopologyView[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [graph, setGraph] = useState<TopologyRender | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [contextReady, setContextReady] = useState(false);
  const [query, setQuery] = useState("");
  const [loadingViews, setLoadingViews] = useState(true);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadViews = useCallback(async () => {
    setLoadingViews(true);
    try {
      const data = await apiRequest<TopologyView[]>("/topology/views");
      setViews(data);
      if (!data.length) {
        setGraph(null);
        setSelectedNodeId(null);
      }
      setSelectedId((current) =>
        current && data.some((item) => item.artifact_id === current)
          ? current
          : data[0]?.artifact_id || null,
      );
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load published topology views");
    } finally {
      setLoadingViews(false);
    }
  }, []);

  const loadGraph = useCallback(async (artifactId: string) => {
    setLoadingGraph(true);
    try {
      const data = await apiRequest<TopologyRender>(
        `/topology/views/${artifactId}/render`,
      );
      setGraph(data);
      setSelectedNodeId((current) =>
        current && data.nodes.some((node) => node.id === current) ? current : null,
      );
      setError(null);
    } catch (cause) {
      setGraph(null);
      setError(cause instanceof Error ? cause.message : "Unable to render current topology");
    } finally {
      setLoadingGraph(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setContextReady(true);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadViews(), 0);
    return () => window.clearTimeout(timer);
  }, [loadViews]);

  useEffect(() => {
    if (!selectedId || !contextReady) return;
    const timer = window.setTimeout(() => void loadGraph(selectedId), 0);
    return () => window.clearTimeout(timer);
  }, [contextReady, loadGraph, selectedId]);

  const visibleNodes = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized || !graph) return graph?.nodes || [];
    return graph.nodes.filter((node) =>
      [node.label, node.kind, node.site, node.group, node.status, node.mac_address]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(normalized)),
    );
  }, [graph, query]);

  const visibleNodeIds = useMemo(
    () => new Set(visibleNodes.map((node) => node.id)),
    [visibleNodes],
  );
  const visibleEdges = useMemo(
    () =>
      (graph?.edges || []).filter(
        (edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target),
      ),
    [graph, visibleNodeIds],
  );
  const positions = useMemo(
    () => positionsFor(visibleNodes, graph?.layout || "force"),
    [graph?.layout, visibleNodes],
  );
  const selectedNode = useMemo(
    () => graph?.nodes.find((node) => node.id === selectedNodeId) || null,
    [graph, selectedNodeId],
  );
  const edgePaths = useMemo(() => topologyEdgePaths(visibleEdges, positions), [visibleEdges, positions]);
  const groups = useMemo(
    () =>
      Array.from(new Set((graph?.nodes || []).map((node) => node.group).filter(Boolean))).sort(),
    [graph],
  );

  return (
    <main className="min-h-screen bg-[#f3f5f8] text-[#253044]">
      <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-[#dce0e7] bg-white/95 px-4 backdrop-blur md:px-6">
        <div className="flex min-w-0 items-center gap-3">
          <Link href="/" className="rounded-lg p-2 text-muted-foreground hover:bg-[#eef0f5]" aria-label="Back to AI operator">
            <ArrowLeft className="size-4" />
          </Link>
          <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 text-white shadow-md shadow-indigo-200">
            <Network className="size-[18px]" />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="truncate text-sm font-semibold">Live topology</h1>
              <Badge className="border-violet-200 bg-violet-50 text-[9px] text-violet-700">published capability</Badge>
              {graph?.context ? <Badge className="border-sky-200 bg-sky-50 text-[9px] text-sky-700">Situation context</Badge> : null}
            </div>
            <p className="truncate text-xs text-muted-foreground">{graph?.context ? graph.context.title : "Scoped evidence for the AI operator, rendered from current inventory"}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            onClick={() => selectedId && void loadGraph(selectedId)}
            disabled={!selectedId || loadingGraph}
          >
            <RefreshCw className={cn("size-3.5", loadingGraph && "animate-spin")} />
            <span className="hidden sm:inline">Refresh current state</span>
          </Button>
          <Button asChild size="sm" className="gap-2 bg-[#5856d6] hover:bg-[#4947ad]">
            <Link href="/studio">
              <Wrench className="size-3.5" />
              <span className="hidden sm:inline">Customize in Studio</span>
            </Link>
          </Button>
        </div>
      </header>

      {error ? (
        <div className="flex items-center gap-2 border-b border-red-200 bg-red-50 px-6 py-2 text-xs text-red-700">
          <XCircle className="size-4" /> {error}
        </div>
      ) : null}

      <div className="grid min-h-[calc(100vh-4rem)] grid-cols-1 xl:grid-cols-[284px_minmax(560px,1fr)_300px]">
        <aside className="border-b border-[#dce0e7] bg-white xl:border-b-0 xl:border-r">
          <div className="flex items-center justify-between border-b border-[#e5e8ed] px-4 py-4">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground">Published views</p>
              <p className="mt-1 text-xs text-muted-foreground">Only reviewed versions run here</p>
            </div>
            <button onClick={() => void loadViews()} className="rounded-md p-1.5 text-muted-foreground hover:bg-[#f1f3f6]" aria-label="Refresh published views">
              <RefreshCw className={cn("size-3.5", loadingViews && "animate-spin")} />
            </button>
          </div>
          <div className="max-h-[280px] space-y-2 overflow-y-auto p-3 xl:max-h-[calc(100vh-9rem)]">
            {views.map((view) => (
              <button
                key={view.artifact_id}
                onClick={() => {
                  setSelectedId(view.artifact_id);
                  setSelectedNodeId(null);
                  setQuery("");
                }}
                className={cn(
                  "w-full rounded-xl border p-3 text-left transition",
                  selectedId === view.artifact_id
                    ? "border-violet-300 bg-violet-50/70 shadow-sm"
                    : "border-[#e2e5ea] bg-white hover:border-[#c9cdd5] hover:bg-[#fafbfc]",
                )}
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="truncate text-xs font-semibold">{view.name}</span>
                  <Badge variant="outline" className="shrink-0 text-[9px]">v{view.version}</Badge>
                </div>
                <p className="mt-1.5 line-clamp-2 text-[10px] leading-4 text-muted-foreground">{view.description}</p>
                <div className="mt-3 flex items-center gap-3 text-[9px] text-muted-foreground">
                  <span className="flex items-center gap-1"><Layers3 className="size-3" /> {view.node_types.length} node types</span>
                  <span className="flex items-center gap-1"><GitBranch className="size-3" /> {view.edge_types.length} edge types</span>
                </div>
              </button>
            ))}
            {!loadingViews && views.length === 0 ? (
              <div className="rounded-xl border border-dashed border-[#cfd4dc] p-5 text-center">
                <CircleDot className="mx-auto size-6 text-muted-foreground" />
                <p className="mt-3 text-xs font-semibold">No published topology</p>
                <p className="mt-1 text-[10px] leading-4 text-muted-foreground">Create, validate, and publish a topology capability before it can run.</p>
                <Link href="/studio" className="mt-3 inline-flex text-[10px] font-semibold text-[#5856d6] hover:underline">Open Capability Studio</Link>
              </div>
            ) : null}
          </div>
        </aside>

        <section className="min-w-0 p-3 md:p-5">
          <div data-text-surface="dark" className="flex min-h-[660px] flex-col overflow-hidden rounded-2xl border border-[#d9dee6] bg-[#172133] shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-[#1d283b] px-4 py-3">
              <div className="min-w-0">
                <p className="truncate text-xs font-semibold text-white">{graph?.name || "Select a published view"}</p>
                <div className="mt-1 flex flex-wrap items-center gap-3 text-[9px] text-muted-foreground">
                  {graph ? <span>Rendered {relativeTime(graph.rendered_at)}</span> : null}
                  {graph ? <span>{graph.node_count} nodes · {graph.edge_count} relationships</span> : null}
                  {graph?.scope_applied ? <span className="flex items-center gap-1 text-emerald-300"><ShieldCheck className="size-3" /> authorization scope applied</span> : null}
                  {graph?.context ? <span className="text-sky-300">deterministic context · not root cause</span> : null}
                </div>
              </div>
              <div className="relative w-full sm:w-60">
                <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Find node, kind, or site" className="h-8 border-white/10 bg-black/20 pl-8 text-xs text-slate-100 placeholder:text-muted-foreground" />
              </div>
            </div>

            <div className="relative min-h-[560px] flex-1">
              {graph && graph.node_count > 0 ? (
                <svg viewBox="0 0 1000 620" className="absolute inset-0 size-full" role="group" aria-label={`${graph.name} current topology`}>
                  <defs>
                    <pattern id="topology-grid" width="28" height="28" patternUnits="userSpaceOnUse">
                      <path d="M 28 0 L 0 0 0 28" fill="none" stroke="#314057" strokeWidth="0.55" opacity="0.55" />
                    </pattern>
                    <filter id="node-shadow" x="-50%" y="-50%" width="200%" height="200%">
                      <feDropShadow dx="0" dy="2" stdDeviation="3" floodColor="#050a12" floodOpacity="0.5" />
                    </filter>
                  </defs>
                  <rect width="1000" height="620" fill="url(#topology-grid)" />
                  {visibleEdges.map((edge) => {
                    const path = edgePaths.get(edge.id);
                    if (!path) return null;
                    return (
                      <g key={edge.id}>
                        <title>{edge.label}{edge.metadata.vlan_id != null ? ` · VLAN ${edge.metadata.vlan_id}` : ""} · {edge.edge_type}</title>
                        <path
                          d={path}
                          fill="none"
                          stroke={edgeStroke(edge)}
                          strokeWidth="1.5"
                          strokeDasharray={edge.edge_type === "wireless_association" ? "7 5" : undefined}
                          opacity="0.82"
                        />
                      </g>
                    );
                  })}
                  {visibleNodes.map((node) => {
                    const point = positions.get(node.id);
                    if (!point) return null;
                    const palette = nodePalette[node.node_type];
                    const active = node.id === selectedNodeId;
                    const label = node.label.length > 24 ? `${node.label.slice(0, 23)}…` : node.label;
                    return (
                      <g key={node.id} role="button" aria-label={`${node.label} · ${node.group || node.node_type}`} aria-pressed={active} tabIndex={0} className="cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-white" onClick={() => setSelectedNodeId(node.id)} onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setSelectedNodeId(node.id);
                        }
                      }}>
                        <circle cx={point.x} cy={point.y} r={active ? 17 : 14} fill={palette.halo} opacity={active ? 0.42 : 0.18} />
                        <circle cx={point.x} cy={point.y} r={active ? 10 : 8} fill={palette.fill} stroke={active ? "#ffffff" : "#dce5f2"} strokeWidth={active ? 3 : 1.5} filter="url(#node-shadow)" />
                        <text x={point.x} y={point.y + 23} textAnchor="middle" fill="#e6edf7" fontSize="9" fontWeight={active ? 700 : 500}>{label}</text>
                        {node.group ? <text x={point.x} y={point.y + 35} textAnchor="middle" fill="var(--muted-foreground)" fontSize="7">{node.group}</text> : null}
                      </g>
                    );
                  })}
                </svg>
              ) : graph && !loadingGraph ? (
                <div className="absolute inset-0 grid place-items-center p-8 text-center">
                  <div className="max-w-sm">
                    <span className="mx-auto grid size-12 place-items-center rounded-2xl border border-white/10 bg-white/5 text-muted-foreground"><LockKeyhole className="size-5" /></span>
                    <p className="mt-4 text-sm font-semibold text-slate-200">No visible inventory in this view</p>
                    <p className="mt-2 text-xs leading-5 text-muted-foreground">The view is valid, but its selectors and your authorization scope currently produce an empty graph.</p>
                  </div>
                </div>
              ) : (
                <div className="absolute inset-0 grid place-items-center">
                  <Activity className={cn("size-6 text-violet-400", loadingGraph && "animate-pulse")} />
                </div>
              )}

              {graph && (graph.nodes_truncated || graph.edges_truncated) ? (
                <div className="absolute bottom-3 left-3 rounded-lg border border-amber-300/20 bg-amber-400/10 px-3 py-2 text-[9px] text-amber-200 backdrop-blur">
                  Bounded result: showing up to {graph.limits.nodes} nodes and {graph.limits.edges} relationships.
                </div>
              ) : null}
              {query && graph ? (
                <div className="absolute right-3 top-3 rounded-lg border border-white/10 bg-black/25 px-3 py-1.5 text-[9px] text-slate-300 backdrop-blur">
                  {visibleNodes.length} matching nodes · {visibleEdges.length} connecting edges
                </div>
              ) : null}
            </div>

            <div className="flex flex-wrap items-center gap-4 border-t border-white/10 bg-[#1d283b] px-4 py-2.5 text-[9px] text-muted-foreground">
              {(Object.keys(nodePalette) as NodeType[]).map((type) => (
                <span key={type} className="flex items-center gap-1.5"><span className="size-2 rounded-full" style={{ backgroundColor: nodePalette[type].fill }} /> {nodePalette[type].label}</span>
              ))}
              {graph ? <span className="ml-auto">{graph.layout} layout · grouped by {graph.group_by}</span> : null}
            </div>
          </div>
        </section>

        <aside className="border-t border-[#dce0e7] bg-[#fafbfc] xl:border-l xl:border-t-0">
          <div className="border-b border-[#e2e6eb] p-5">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground"><Bot className="size-3.5 text-violet-600" /> Operator context</div>
            <p className="mt-2 text-xs leading-5 text-[#637084]">This page exposes a minimized, scope-filtered graph. The AI operator can query the same entities through governed tools without receiving raw collector payloads.</p>
            <Link href="/" className="mt-4 inline-flex items-center gap-2 text-xs font-semibold text-[#5856d6] hover:text-[#3f3da4]"><Sparkles className="size-3.5" /> Ask the AI operator</Link>
          </div>

          <div className="border-b border-[#e2e6eb] p-5">
            <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Selected node</p>
            {selectedNode ? (
              <dl className="mt-4 grid grid-cols-2 gap-3 text-xs">
                <div className="col-span-2"><dt className="text-[10px] text-muted-foreground">Name</dt><dd className="mt-1 break-words font-semibold">{selectedNode.label}</dd></div>
                  <div><dt className="text-[10px] text-muted-foreground">Type</dt><dd className="mt-1">{nodePalette[selectedNode.node_type].label}</dd></div>
                  <div><dt className="text-[10px] text-muted-foreground">Status</dt><dd className="mt-1">{selectedNode.status}</dd></div>
                  <div><dt className="text-[10px] text-muted-foreground">Kind</dt><dd className="mt-1 break-words">{selectedNode.kind}</dd></div>
                  <div><dt className="text-[10px] text-muted-foreground">Site</dt><dd className="mt-1 break-words">{selectedNode.site || "Not assigned"}</dd></div>
                {selectedNode.mac_address ? <div className="col-span-2"><dt className="text-[10px] text-muted-foreground">MAC address</dt><dd className="mt-1 font-mono text-[10px]">{selectedNode.mac_address}</dd></div> : null}
                {selectedNode.external_key ? <div className="col-span-2"><dt className="text-[10px] text-muted-foreground">External key</dt><dd className="mt-1 break-all font-mono text-[10px]">{selectedNode.external_key}</dd></div> : null}
              </dl>
            ) : (
              <p className="mt-3 text-xs leading-5 text-muted-foreground">Select a node in the graph to inspect its safe operational identity.</p>
            )}
          </div>

          <div className="border-b border-[#e2e6eb] p-5">
            <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">View contract</p>
            {graph ? (
              <div className="mt-3 space-y-3 text-[10px]">
                <div className="flex items-center justify-between gap-2"><span className="text-muted-foreground">Immutable version</span><span className="font-semibold">v{graph.version}</span></div>
                <div className="flex items-center justify-between gap-2"><span className="text-muted-foreground">Content hash</span><span className="font-mono" title={graph.content_hash}>{shortHash(graph.content_hash)}</span></div>
                <div className="flex items-center justify-between gap-2"><span className="text-muted-foreground">Scope</span><span className={graph.scope_applied ? "text-emerald-700" : "text-[#59677b]"}>{graph.scope_applied ? "Object-filtered" : "Global"}</span></div>
                <div className="flex items-center justify-between gap-2"><span className="text-muted-foreground">Published</span><span>{relativeTime(graph.published_at)}</span></div>
                {groups.length ? <div><span className="text-muted-foreground">Visible groups</span><div className="mt-2 flex flex-wrap gap-1">{groups.slice(0, 12).map((group) => <Badge key={group} variant="outline" className="text-[9px]">{group}</Badge>)}</div></div> : null}
              </div>
            ) : <p className="mt-3 text-xs text-muted-foreground">No active view.</p>}
          </div>

          <div className="p-5">
            <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Related workspaces</p>
            <div className="mt-3 space-y-2">
              <Link href="/assets/devices" className="flex items-center gap-2 rounded-lg border border-[#e0e4e9] bg-white px-3 py-2.5 text-xs font-medium hover:border-violet-200 hover:text-violet-700"><Boxes className="size-3.5" /> Device onboarding</Link>
              <Link href="/studio" className="flex items-center gap-2 rounded-lg border border-[#e0e4e9] bg-white px-3 py-2.5 text-xs font-medium hover:border-violet-200 hover:text-violet-700"><Wrench className="size-3.5" /> Capability Studio</Link>
            </div>
          </div>
        </aside>
      </div>
    </main>
  );
}
