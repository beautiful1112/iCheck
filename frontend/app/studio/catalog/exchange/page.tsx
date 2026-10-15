"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  CloudCog,
  RefreshCw,
  RotateCcw,
  Send,
  ServerCog,
  ShieldCheck,
  Unplug,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type EndpointKind =
  | "transparency_witness"
  | "promotion_target"
  | "gossip_peer";
type TLSMode = "server_auth" | "mutual_tls";
type JobStatus =
  | "pending"
  | "processing"
  | "retry"
  | "succeeded"
  | "dead_letter"
  | "cancelled";

type Endpoint = {
  id: string;
  name: string;
  kind: EndpointKind;
  url: string;
  credential_configured: boolean;
  tls_mode: TLSMode;
  tls_ca_certificate_ref: string | null;
  tls_client_certificate_ref: string | null;
  tls_client_private_key_ref: string | null;
  tls_client_private_key_password_ref: string | null;
  custom_ca_configured: boolean;
  mutual_tls_configured: boolean;
  tls_revision: number;
  witness_id: string | null;
  target_environment_id: string | null;
  target_stage: string | null;
  target_region_id: string | null;
  auto_dispatch: boolean;
  enabled: boolean;
};

type Witness = {
  id: string;
  name: string;
  witness_id: string;
  region: string;
  enabled: boolean;
};

type Job = {
  id: string;
  endpoint_name: string;
  kind: "witness_checkpoint" | "promotion_delivery" | "gossip_delivery";
  dedupe_key: string;
  status: JobStatus;
  attempt_count: number;
  max_attempts: number;
  response_digest_sha256: string | null;
  error_type: string | null;
  error_sha256: string | null;
  created_at: string;
};

type Health = {
  workers_online: number;
  workers_stale: number;
  pending: number;
  processing: number;
  retry: number;
  succeeded: number;
  dead_letter: number;
};

const inputClass =
  "h-9 border-[#d8dbe0] bg-white text-xs placeholder:text-muted-foreground";
const selectClass =
  "h-9 w-full rounded-md border border-[#d8dbe0] bg-white px-3 text-xs outline-none";

function shortDigest(value: string | null) {
  if (!value) return "—";
  return value.slice(0, 10) + "…" + value.slice(-6);
}

function statusClass(value: JobStatus) {
  if (value === "succeeded") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }
  if (value === "dead_letter") {
    return "border-red-200 bg-red-50 text-red-700";
  }
  if (value === "retry") {
    return "border-amber-200 bg-amber-50 text-amber-700";
  }
  return "border-cyan-200 bg-cyan-50 text-cyan-700";
}

export default function EcosystemExchangePage() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [witnesses, setWitnesses] = useState<Witness[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [kind, setKind] = useState<EndpointKind>("transparency_witness");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [credentialRef, setCredentialRef] = useState("");
  const [tlsMode, setTlsMode] = useState<TLSMode>("server_auth");
  const [tlsCaRef, setTlsCaRef] = useState("");
  const [tlsClientCertificateRef, setTlsClientCertificateRef] = useState("");
  const [tlsClientPrivateKeyRef, setTlsClientPrivateKeyRef] = useState("");
  const [tlsClientPrivateKeyPasswordRef, setTlsClientPrivateKeyPasswordRef] =
    useState("");
  const [witnessId, setWitnessId] = useState("");
  const [targetEnvironment, setTargetEnvironment] = useState("");
  const [targetStage, setTargetStage] = useState("production");
  const [targetRegion, setTargetRegion] = useState("");
  const [autoDispatch, setAutoDispatch] = useState(true);
  const [offerId, setOfferId] = useState("");
  const [witnessEndpointId, setWitnessEndpointId] = useState("");
  const [gossipEndpointId, setGossipEndpointId] = useState("");
  const [promotionEndpointId, setPromotionEndpointId] = useState("");
  const [signedEnvelope, setSignedEnvelope] = useState("");
  const [deliveryReason, setDeliveryReason] = useState("");
  const [rotationEndpointId, setRotationEndpointId] = useState("");
  const [rotationTlsMode, setRotationTlsMode] =
    useState<TLSMode>("server_auth");
  const [rotationCaRef, setRotationCaRef] = useState("");
  const [rotationCertificateRef, setRotationCertificateRef] = useState("");
  const [rotationPrivateKeyRef, setRotationPrivateKeyRef] = useState("");
  const [rotationPasswordRef, setRotationPasswordRef] = useState("");
  const [rotationReason, setRotationReason] = useState("");

  const load = useCallback(async (preferredRotationEndpointId?: string) => {
    setLoading(true);
    try {
      const [endpointRows, witnessRows, jobRows, healthState] =
        await Promise.all([
          apiFetch<Endpoint[]>("/ecosystem-transport/endpoints?limit=500"),
          apiFetch<Witness[]>("/transparency-witnessing/witnesses?limit=500"),
          apiFetch<Job[]>("/ecosystem-transport/jobs?limit=500"),
          apiFetch<Health>("/ecosystem-transport/health"),
        ]);
      setEndpoints(endpointRows);
      setWitnesses(witnessRows);
      setJobs(jobRows);
      setHealth(healthState);
      const rotationEndpoint =
        endpointRows.find(
          (item) => item.id === preferredRotationEndpointId,
        ) || endpointRows[0];
      if (rotationEndpoint) {
        setRotationEndpointId(rotationEndpoint.id);
        setRotationTlsMode(rotationEndpoint.tls_mode);
        setRotationCaRef(rotationEndpoint.tls_ca_certificate_ref || "");
        setRotationCertificateRef(
          rotationEndpoint.tls_client_certificate_ref || "",
        );
        setRotationPrivateKeyRef(
          rotationEndpoint.tls_client_private_key_ref || "",
        );
        setRotationPasswordRef(
          rotationEndpoint.tls_client_private_key_password_ref || "",
        );
      }
      setWitnessId((current) => current || witnessRows[0]?.id || "");
      setWitnessEndpointId(
        (current) =>
          current ||
          endpointRows.find((item) => item.kind === "transparency_witness")
            ?.id ||
          "",
      );
      setPromotionEndpointId(
        (current) =>
          current ||
          endpointRows.find((item) => item.kind === "promotion_target")?.id ||
          "",
      );
      setGossipEndpointId(
        (current) =>
          current ||
          endpointRows.find((item) => item.kind === "gossip_peer")?.id ||
          "",
      );
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to load ecosystem transport",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  function selectRotationEndpoint(endpointId: string) {
    setRotationEndpointId(endpointId);
    const endpoint = endpoints.find((item) => item.id === endpointId);
    if (!endpoint) return;
    setRotationTlsMode(endpoint.tls_mode);
    setRotationCaRef(endpoint.tls_ca_certificate_ref || "");
    setRotationCertificateRef(endpoint.tls_client_certificate_ref || "");
    setRotationPrivateKeyRef(endpoint.tls_client_private_key_ref || "");
    setRotationPasswordRef(
      endpoint.tls_client_private_key_password_ref || "",
    );
  }

  async function createEndpoint() {
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      await apiFetch<Endpoint>("/ecosystem-transport/endpoints", {
        method: "POST",
        body: JSON.stringify({
          name,
          kind,
          url,
          credential_profile_ref: credentialRef || null,
          tls_mode: tlsMode,
          tls_ca_certificate_ref: tlsCaRef || null,
          tls_client_certificate_ref:
            tlsMode === "mutual_tls" ? tlsClientCertificateRef || null : null,
          tls_client_private_key_ref:
            tlsMode === "mutual_tls" ? tlsClientPrivateKeyRef || null : null,
          tls_client_private_key_password_ref:
            tlsMode === "mutual_tls"
              ? tlsClientPrivateKeyPasswordRef || null
              : null,
          witness_id: kind === "transparency_witness" ? witnessId : null,
          target_environment_id:
            kind === "promotion_target" ? targetEnvironment : null,
          target_stage: kind === "promotion_target" ? targetStage : null,
          target_region_id: kind === "gossip_peer" ? targetRegion : null,
          auto_dispatch: kind !== "promotion_target" ? autoDispatch : false,
          enabled: true,
          request_timeout_seconds: 10,
          max_response_bytes: 1000000,
          created_by: "studio.operator",
        }),
      });
      setName("");
      setUrl("");
      setTlsCaRef("");
      setTlsClientCertificateRef("");
      setTlsClientPrivateKeyRef("");
      setTlsClientPrivateKeyPasswordRef("");
      setTargetRegion("");
      setMessage("Endpoint pinned to its exact trust boundary.");
      await load(rotationEndpointId);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Create failed");
    } finally {
      setSaving(false);
    }
  }

  async function rotateEndpointIdentity() {
    const endpoint = endpoints.find((item) => item.id === rotationEndpointId);
    if (!endpoint) return;
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      await apiFetch<Endpoint>(
        "/ecosystem-transport/endpoints/" + endpoint.id + "/tls",
        {
          method: "PUT",
          body: JSON.stringify({
            tls_mode: rotationTlsMode,
            tls_ca_certificate_ref: rotationCaRef || null,
            tls_client_certificate_ref:
              rotationTlsMode === "mutual_tls"
                ? rotationCertificateRef || null
                : null,
            tls_client_private_key_ref:
              rotationTlsMode === "mutual_tls"
                ? rotationPrivateKeyRef || null
                : null,
            tls_client_private_key_password_ref:
              rotationTlsMode === "mutual_tls"
                ? rotationPasswordRef || null
                : null,
            expected_tls_revision: endpoint.tls_revision,
            reason: rotationReason,
            actor: "studio.operator",
          }),
        },
      );
      setRotationReason("");
      setMessage(
        "Transport identity rotated with revision conflict protection.",
      );
      await load(endpoint.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "TLS rotation failed");
    } finally {
      setSaving(false);
    }
  }

  async function dispatchWitness() {
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      await apiFetch<Job[]>(
        "/ecosystem-transport/witness-offers/" + offerId + "/dispatch",
        {
          method: "POST",
          body: JSON.stringify({
            endpoint_ids: witnessEndpointId ? [witnessEndpointId] : [],
            max_attempts: 5,
            actor: "studio.operator",
          }),
        },
      );
      setMessage("Checkpoint queued for independent witnessing.");
      await load(rotationEndpointId);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Dispatch failed");
    } finally {
      setSaving(false);
    }
  }

  async function dispatchGossip() {
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      await apiFetch<Job[]>(
        "/ecosystem-transport/gossip-offers/" + offerId + "/dispatch",
        {
          method: "POST",
          body: JSON.stringify({
            endpoint_ids: gossipEndpointId ? [gossipEndpointId] : [],
            max_attempts: 5,
            actor: "studio.operator",
          }),
        },
      );
      setMessage("Quorum-backed checkpoint queued for regional gossip.");
      await load(rotationEndpointId);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Gossip dispatch failed");
    } finally {
      setSaving(false);
    }
  }

  async function deliverPromotion() {
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      await apiFetch<Job>("/ecosystem-transport/promotion-deliveries", {
        method: "POST",
        body: JSON.stringify({
          endpoint_id: promotionEndpointId,
          signed_attestation: JSON.parse(signedEnvelope),
          reason: deliveryReason,
          max_attempts: 5,
          actor: "studio.operator",
        }),
      });
      setMessage(
        "Signed envelope queued; the target still performs independent acceptance.",
      );
      await load(rotationEndpointId);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Delivery failed");
    } finally {
      setSaving(false);
    }
  }

  async function jobAction(job: Job, action: "retry" | "cancel") {
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      await apiFetch<Job>(
        "/ecosystem-transport/jobs/" + job.id + "/" + action,
        {
          method: "POST",
          body: JSON.stringify({
            reason: "Operator reviewed this durable delivery.",
            actor: "studio.operator",
          }),
        },
      );
      setMessage(action === "retry" ? "Job re-queued." : "Job cancelled.");
      await load(rotationEndpointId);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Job action failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#eef0f5] text-[#253044]">
      <header className="flex min-h-16 items-center justify-between border-b border-[#d8dbe0] bg-white px-5 py-3">
        <div className="flex items-center gap-3">
          <Link
            href="/studio/catalog"
            className="rounded-md p-2 text-[#59677b] hover:bg-[#eef0f5]"
            aria-label="Back to Capability Catalog"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#171c2a] text-white">
            <CloudCog className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-semibold">Ecosystem Exchange</h1>
              <Badge className="border-violet-200 bg-violet-50 text-[10px] text-violet-700">
                signed transport
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground">
              Durable delivery only · trust remains at each independent boundary
            </p>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="gap-2"
          onClick={() => void load(rotationEndpointId)}
          disabled={loading}
        >
          <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
          Refresh
        </Button>
      </header>

      {(error || message) && (
        <div
          className={cn(
            "flex items-center gap-2 border-b px-5 py-2 text-xs",
            error
              ? "border-red-200 bg-red-50 text-red-700"
              : "border-emerald-200 bg-emerald-50 text-emerald-700",
          )}
        >
          {error ? (
            <XCircle className="h-4 w-4" />
          ) : (
            <CheckCircle2 className="h-4 w-4" />
          )}
          {error || message}
        </div>
      )}

      <section className="grid grid-cols-5 gap-px border-b border-[#d8dbe0] bg-[#d8dbe0]">
        {[
          ["Live workers", health?.workers_online || 0, ServerCog],
          ["Ready", (health?.pending || 0) + (health?.retry || 0), Send],
          ["Processing", health?.processing || 0, CloudCog],
          ["Succeeded", health?.succeeded || 0, ShieldCheck],
          ["Dead letter", health?.dead_letter || 0, Unplug],
        ].map(([label, value, Icon]) => {
          const SummaryIcon = Icon as typeof ServerCog;
          return (
            <div key={String(label)} className="flex items-center gap-3 bg-white px-5 py-3">
              <SummaryIcon className="h-4 w-4 text-violet-600" />
              <div>
                <div className="text-lg font-semibold leading-none">
                  {String(value)}
                </div>
                <div className="mt-1 text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
                  {String(label)}
                </div>
              </div>
            </div>
          );
        })}
      </section>

      <div className="grid gap-4 p-5 xl:grid-cols-[390px_minmax(0,1fr)]">
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Pin an exchange endpoint</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <select
                className={selectClass}
                value={kind}
                onChange={(event) => {
                  const value = event.target.value as EndpointKind;
                  setKind(value);
                  setAutoDispatch(value !== "promotion_target");
                }}
                aria-label="Endpoint kind"
              >
                <option value="transparency_witness">Independent witness</option>
                <option value="promotion_target">Promotion target</option>
                <option value="gossip_peer">Regional gossip peer</option>
              </select>
              <Input className={inputClass} value={name} onChange={(event) => setName(event.target.value)} placeholder="Endpoint name" />
              <Input className={inputClass} value={url} onChange={(event) => setUrl(event.target.value)} placeholder="Exact HTTPS endpoint URL" />
              <Input className={inputClass} value={credentialRef} onChange={(event) => setCredentialRef(event.target.value)} placeholder="Credential profile ID or name (optional)" />
              <div className="rounded-md border border-[#e1e4e9] bg-[#fafbfc] p-3">
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[#59677b]">
                    Workload identity
                  </span>
                  <span className="text-[9px] text-muted-foreground">references only</span>
                </div>
                <div className="space-y-2">
                  <select className={selectClass} value={tlsMode} onChange={(event) => setTlsMode(event.target.value as TLSMode)} aria-label="TLS mode">
                    <option value="server_auth">Server-authenticated TLS</option>
                    <option value="mutual_tls">Mutual TLS (mTLS)</option>
                  </select>
                  <Input className={inputClass} value={tlsCaRef} onChange={(event) => setTlsCaRef(event.target.value)} placeholder="Custom CA credential profile (optional)" />
                  {tlsMode === "mutual_tls" && (
                    <>
                      <Input className={inputClass} value={tlsClientCertificateRef} onChange={(event) => setTlsClientCertificateRef(event.target.value)} placeholder="Client certificate credential profile" />
                      <Input className={inputClass} value={tlsClientPrivateKeyRef} onChange={(event) => setTlsClientPrivateKeyRef(event.target.value)} placeholder="Client private-key credential profile" />
                      <Input className={inputClass} value={tlsClientPrivateKeyPasswordRef} onChange={(event) => setTlsClientPrivateKeyPasswordRef(event.target.value)} placeholder="Private-key password profile (optional)" />
                    </>
                  )}
                </div>
              </div>
              {kind === "transparency_witness" ? (
                <>
                  <select className={selectClass} value={witnessId} onChange={(event) => setWitnessId(event.target.value)} aria-label="Pinned witness">
                    <option value="">Select pinned witness identity</option>
                    {witnesses.filter((item) => item.enabled).map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.name} · {item.region}
                      </option>
                    ))}
                  </select>
                  <label className="flex items-center gap-2 text-xs text-[#59677b]">
                    <input type="checkbox" checked={autoDispatch} onChange={(event) => setAutoDispatch(event.target.checked)} />
                    Automatically queue each live checkpoint
                  </label>
                </>
              ) : kind === "promotion_target" ? (
                <div className="grid grid-cols-[1fr_130px] gap-2">
                  <Input className={inputClass} value={targetEnvironment} onChange={(event) => setTargetEnvironment(event.target.value)} placeholder="Target environment" />
                  <select className={selectClass} value={targetStage} onChange={(event) => setTargetStage(event.target.value)} aria-label="Target stage">
                    {["development", "test", "staging", "production"].map((stage) => (
                      <option key={stage} value={stage}>{stage}</option>
                    ))}
                  </select>
                </div>
              ) : (
                <>
                  <Input className={inputClass} value={targetRegion} onChange={(event) => setTargetRegion(event.target.value)} placeholder="Pinned target region ID" />
                  <label className="flex items-center gap-2 text-xs text-[#59677b]">
                    <input type="checkbox" checked={autoDispatch} onChange={(event) => setAutoDispatch(event.target.checked)} />
                    Automatically deliver each quorum-backed checkpoint
                  </label>
                </>
              )}
              <Button className="w-full" onClick={() => void createEndpoint()} disabled={saving || !name || !url || (kind === "gossip_peer" && !targetRegion) || (tlsMode === "mutual_tls" && (!tlsClientCertificateRef || !tlsClientPrivateKeyRef))}>
                Pin endpoint
              </Button>
              <p className="text-[10px] leading-4 text-muted-foreground">
                The worker enforces the HTTPS host allowlist. Secret values never
                enter this API or a delivery job.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Rotate transport identity</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <select className={selectClass} value={rotationEndpointId} onChange={(event) => selectRotationEndpoint(event.target.value)} aria-label="Endpoint to rotate">
                <option value="">Select endpoint</option>
                {endpoints.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name} · revision {item.tls_revision}
                  </option>
                ))}
              </select>
              <select className={selectClass} value={rotationTlsMode} onChange={(event) => setRotationTlsMode(event.target.value as TLSMode)} aria-label="Rotated TLS mode">
                <option value="server_auth">Server-authenticated TLS</option>
                <option value="mutual_tls">Mutual TLS (mTLS)</option>
              </select>
              <Input className={inputClass} value={rotationCaRef} onChange={(event) => setRotationCaRef(event.target.value)} placeholder="Custom CA credential profile (optional)" />
              {rotationTlsMode === "mutual_tls" && (
                <>
                  <Input className={inputClass} value={rotationCertificateRef} onChange={(event) => setRotationCertificateRef(event.target.value)} placeholder="Client certificate credential profile" />
                  <Input className={inputClass} value={rotationPrivateKeyRef} onChange={(event) => setRotationPrivateKeyRef(event.target.value)} placeholder="Client private-key credential profile" />
                  <Input className={inputClass} value={rotationPasswordRef} onChange={(event) => setRotationPasswordRef(event.target.value)} placeholder="Private-key password profile (optional)" />
                </>
              )}
              <Input className={inputClass} value={rotationReason} onChange={(event) => setRotationReason(event.target.value)} placeholder="Rotation reason" />
              <Button variant="outline" className="w-full gap-2" onClick={() => void rotateEndpointIdentity()} disabled={saving || !rotationEndpointId || rotationReason.length < 3 || (rotationTlsMode === "mutual_tls" && (!rotationCertificateRef || !rotationPrivateKeyRef))}>
                <ShieldCheck className="h-3.5 w-3.5" /> Rotate identity
              </Button>
              <p className="text-[10px] leading-4 text-muted-foreground">
                Uses the current TLS revision as an optimistic lock. Paste
                Credential Profile IDs or names, never PEM or key material.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Explicit delivery</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input className={inputClass} value={offerId} onChange={(event) => setOfferId(event.target.value)} placeholder="Checkpoint offer ID" />
              <select className={selectClass} value={witnessEndpointId} onChange={(event) => setWitnessEndpointId(event.target.value)} aria-label="Witness endpoint">
                <option value="">All enabled witness endpoints</option>
                {endpoints.filter((item) => item.kind === "transparency_witness").map((item) => (
                  <option key={item.id} value={item.id}>{item.name}</option>
                ))}
              </select>
              <Button variant="outline" className="w-full gap-2" onClick={() => void dispatchWitness()} disabled={saving || !offerId}>
                <Send className="h-3.5 w-3.5" /> Queue witness request
              </Button>
              <div className="border-t border-[#e1e4e9] pt-4">
                <select className={selectClass} value={gossipEndpointId} onChange={(event) => setGossipEndpointId(event.target.value)} aria-label="Gossip endpoint">
                  <option value="">All enabled gossip peers</option>
                  {endpoints.filter((item) => item.kind === "gossip_peer").map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </select>
                <Button variant="outline" className="mt-2 w-full gap-2" onClick={() => void dispatchGossip()} disabled={saving || !offerId}>
                  <Send className="h-3.5 w-3.5" /> Queue regional gossip
                </Button>
              </div>
              <div className="border-t border-[#e1e4e9] pt-4">
                <select className={selectClass} value={promotionEndpointId} onChange={(event) => setPromotionEndpointId(event.target.value)} aria-label="Promotion endpoint">
                  <option value="">Select promotion target</option>
                  {endpoints.filter((item) => item.kind === "promotion_target").map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </select>
                <textarea
                  className="mt-2 min-h-32 w-full rounded-md border border-[#d8dbe0] bg-white p-3 font-mono text-[10px]"
                  value={signedEnvelope}
                  onChange={(event) => setSignedEnvelope(event.target.value)}
                  placeholder="Paste signed promotion envelope JSON"
                  aria-label="Signed promotion envelope"
                />
                <Input className={cn(inputClass, "mt-2")} value={deliveryReason} onChange={(event) => setDeliveryReason(event.target.value)} placeholder="Delivery reason" />
                <Button variant="outline" className="mt-2 w-full gap-2" onClick={() => void deliverPromotion()} disabled={saving || !promotionEndpointId || !signedEnvelope || deliveryReason.length < 3}>
                  <Send className="h-3.5 w-3.5" /> Queue signed envelope
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Pinned boundaries</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 lg:grid-cols-2">
              {endpoints.length === 0 && <p className="text-xs text-muted-foreground">No endpoints configured.</p>}
              {endpoints.map((endpoint) => (
                <div key={endpoint.id} className="rounded-lg border border-[#d8dbe0] bg-[#fafbfc] p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-xs font-semibold">{endpoint.name}</div>
                    <Badge className={cn("text-[9px]", endpoint.enabled ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-slate-200 bg-slate-50 text-muted-foreground")}>
                      {endpoint.enabled ? "enabled" : "disabled"}
                    </Badge>
                  </div>
                  <div className="mt-1 break-all text-[10px] text-muted-foreground">{endpoint.url}</div>
                  <div className="mt-3 grid grid-cols-2 gap-2 text-[10px] text-[#59677b]">
                    <span>{endpoint.kind.replaceAll("_", " ")}</span>
                    <span>{endpoint.credential_configured ? "credential isolated" : "no bearer token"}</span>
                    <span>{endpoint.target_environment_id || endpoint.target_region_id || endpoint.witness_id || "—"}</span>
                    <span>{endpoint.auto_dispatch ? "automatic" : "explicit only"}</span>
                    <span>{endpoint.tls_mode === "mutual_tls" ? "mTLS" : "server TLS"} · r{endpoint.tls_revision}</span>
                    <span>{endpoint.custom_ca_configured ? "custom CA" : "system trust"}</span>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Durable delivery ledger</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {jobs.length === 0 && <p className="text-xs text-muted-foreground">No jobs queued.</p>}
              {jobs.map((job) => (
                <div key={job.id} className="grid gap-3 rounded-lg border border-[#d8dbe0] bg-white p-3 md:grid-cols-[minmax(180px,1.2fr)_1fr_150px]">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold">{job.endpoint_name}</span>
                      <Badge className={cn("text-[9px]", statusClass(job.status))}>
                        {job.status.replaceAll("_", " ")}
                      </Badge>
                    </div>
                    <div className="mt-1 text-[10px] text-muted-foreground">
                      {job.kind.replaceAll("_", " ")} · attempt {job.attempt_count}/{job.max_attempts}
                    </div>
                  </div>
                  <div className="space-y-1 font-mono text-[9px] text-[#59677b]">
                    <div>dedupe {shortDigest(job.dedupe_key)}</div>
                    <div>response {shortDigest(job.response_digest_sha256)}</div>
                    {job.error_type && <div className="text-red-600">{job.error_type} · {shortDigest(job.error_sha256)}</div>}
                  </div>
                  <div className="flex justify-end gap-2">
                    {["retry", "dead_letter", "cancelled"].includes(job.status) && (
                      <Button variant="outline" size="sm" className="h-7 gap-1 text-[10px]" onClick={() => void jobAction(job, "retry")} disabled={saving}>
                        <RotateCcw className="h-3 w-3" /> Retry
                      </Button>
                    )}
                    {["pending", "retry", "dead_letter"].includes(job.status) && (
                      <Button variant="outline" size="sm" className="h-7 text-[10px]" onClick={() => void jobAction(job, "cancel")} disabled={saving}>
                        Cancel
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </main>
  );
}
