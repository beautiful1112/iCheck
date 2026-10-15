"use client";

import Link from "next/link";
import { ChangeEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Download,
  Eye,
  FileSignature,
  KeyRound,
  Loader2,
  Network,
  Power,
  RefreshCw,
  ShieldAlert,
  Upload,
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
  NativeSelect,
  NativeSelectOption,
} from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type TrustKey = {
  id: string;
  name: string;
  fingerprint_sha256: string;
  enabled: boolean;
  purposes: string[];
};

type Witness = {
  id: string;
  name: string;
  witness_id: string;
  region: string;
  trust_key_id: string;
  key_fingerprint_sha256: string;
  enabled: boolean;
  updated_at: string;
};

type Policy = {
  required_quorum: number;
  max_attestation_age_hours: number;
  updated_by: string;
  updated_at: string;
};

type CheckpointStatement = {
  format_version: string;
  log_id: string;
  epoch: number;
  sequence: number;
  head_digest_sha256: string;
  issued_at: string;
  expires_at: string;
  digest_sha256: string;
};

type Offer = {
  id: string;
  log_id: string;
  epoch: number;
  sequence: number;
  head_digest_sha256: string;
  statement_digest_sha256: string;
  statement: CheckpointStatement;
  expires_at: string;
  reason: string;
  attestation_count: number;
  required_quorum: number;
  quorum_satisfied: boolean;
};

type Observation = {
  id: string;
  source_region: string;
  log_id: string;
  epoch: number;
  sequence: number;
  head_digest_sha256: string;
  document_digest_sha256: string;
  witness_count: number;
  initial_status: "consistent" | "behind" | "ahead" | "fork";
  current_status: "consistent" | "behind" | "ahead" | "fork";
  received_by: string;
  received_at: string;
};

function shortHash(value: string) {
  return `${value.slice(0, 12)}…`;
}

function downloadJson(document: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(document, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = window.document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function parseObject(value: string, label: string): Record<string, unknown> {
  if (!value.trim()) throw new Error(`Select or paste ${label} JSON first`);
  const document = JSON.parse(value) as Record<string, unknown>;
  if (!document || Array.isArray(document)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return document;
}

export default function TransparencyWitnessesPage() {
  const [keys, setKeys] = useState<TrustKey[]>([]);
  const [witnesses, setWitnesses] = useState<Witness[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [offers, setOffers] = useState<Offer[]>([]);
  const [observations, setObservations] = useState<Observation[]>([]);
  const [keyName, setKeyName] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [witnessName, setWitnessName] = useState("");
  const [externalWitnessId, setExternalWitnessId] = useState("");
  const [region, setRegion] = useState("");
  const [trustKeyId, setTrustKeyId] = useState("");
  const [quorum, setQuorum] = useState("2");
  const [maxAge, setMaxAge] = useState("168");
  const [offerReason, setOfferReason] = useState("");
  const [validityHours, setValidityHours] = useState("24");
  const [offerId, setOfferId] = useState("");
  const [attestationText, setAttestationText] = useState("");
  const [attestationFilename, setAttestationFilename] = useState("");
  const [sourceRegion, setSourceRegion] = useState("primary");
  const [gossipText, setGossipText] = useState("");
  const [gossipFilename, setGossipFilename] = useState("");
  const [gossipReason, setGossipReason] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [keyRows, witnessRows, policyRow, offerRows, gossipRows] =
        await Promise.all([
          apiFetch<TrustKey[]>("/artifact-trust-keys"),
          apiFetch<Witness[]>("/transparency-witnessing/witnesses?limit=500"),
          apiFetch<Policy>("/transparency-witnessing/policy"),
          apiFetch<Offer[]>(
            "/transparency-witnessing/checkpoint-offers?limit=500",
          ),
          apiFetch<Observation[]>("/transparency-witnessing/gossip?limit=500"),
        ]);
      setKeys(keyRows);
      setWitnesses(witnessRows);
      setPolicy(policyRow);
      setOffers(offerRows);
      setObservations(gossipRows);
      setQuorum(String(policyRow.required_quorum));
      setMaxAge(String(policyRow.max_attestation_age_hours));
      const eligible = keyRows.filter(
        (key) => key.enabled && key.purposes.includes("transparency_witness"),
      );
      setTrustKeyId((current) => current || eligible[0]?.id || "");
      setOfferId((current) => current || offerRows[0]?.id || "");
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to load transparency witnesses",
      );
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const witnessKeys = useMemo(
    () => keys.filter(
      (key) => key.enabled && key.purposes.includes("transparency_witness"),
    ),
    [keys],
  );

  async function execute(label: string, action: () => Promise<void>) {
    setBusy(label);
    setError(null);
    setMessage(null);
    try {
      await action();
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Operation failed");
    } finally {
      setBusy(null);
    }
  }

  async function pinWitnessKey() {
    if (!keyName.trim() || !keyPem.trim()) return;
    await execute("key", async () => {
      const created = await apiFetch<TrustKey>("/artifact-trust-keys", {
        method: "POST",
        body: JSON.stringify({
          name: keyName.trim(),
          public_key_pem: keyPem.trim(),
          purposes: ["transparency_witness"],
          created_by: "platform.admin",
        }),
      });
      setTrustKeyId(created.id);
      setKeyName("");
      setKeyPem("");
      setMessage("Witness public key pinned; private key remains external.");
    });
  }

  async function registerWitness() {
    if (
      !witnessName.trim()
      || !externalWitnessId.trim()
      || !region.trim()
      || !trustKeyId
    ) return;
    await execute("witness", async () => {
      await apiFetch<Witness>("/transparency-witnessing/witnesses", {
        method: "POST",
        body: JSON.stringify({
          name: witnessName.trim(),
          witness_id: externalWitnessId.trim(),
          region: region.trim(),
          trust_key_id: trustKeyId,
          created_by: "platform.admin",
        }),
      });
      setWitnessName("");
      setExternalWitnessId("");
      setRegion("");
      setMessage("Independent witness registered with a pinned public key.");
    });
  }

  async function toggleWitness(witness: Witness) {
    await execute(`witness-${witness.id}`, async () => {
      await apiFetch<Witness>(
        `/transparency-witnessing/witnesses/${witness.id}/state`,
        {
          method: "POST",
          body: JSON.stringify({
            enabled: !witness.enabled,
            reason: `${witness.enabled ? "Disable" : "Enable"} witness from Studio.`,
            actor: "platform.admin",
          }),
        },
      );
      setMessage(
        witness.enabled
          ? "Witness disabled; its attestations no longer count toward quorum."
          : "Witness enabled after trust-key revalidation.",
      );
    });
  }

  async function updatePolicy() {
    await execute("policy", async () => {
      await apiFetch<Policy>("/transparency-witnessing/policy", {
        method: "PUT",
        body: JSON.stringify({
          required_quorum: Number(quorum),
          max_attestation_age_hours: Number(maxAge),
          reason: "Update external witness acceptance policy.",
          actor: "platform.admin",
        }),
      });
      setMessage("Witness acceptance policy updated.");
    });
  }

  async function createOffer() {
    if (!offerReason.trim()) return;
    await execute("offer", async () => {
      const created = await apiFetch<Offer>(
        "/transparency-witnessing/checkpoint-offers",
        {
          method: "POST",
          body: JSON.stringify({
            validity_hours: Number(validityHours),
            reason: offerReason.trim(),
            actor: "platform.admin",
          }),
        },
      );
      setOfferId(created.id);
      setOfferReason("");
      setMessage("Immutable checkpoint statement created for external signing.");
    });
  }

  async function readJsonFile(
    event: ChangeEvent<HTMLInputElement>,
    setText: (value: string) => void,
    setFilename: (value: string) => void,
  ) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      setText(await file.text());
      setFilename(file.name);
      setError(null);
    } catch {
      setError("Unable to read the selected JSON file");
    } finally {
      event.target.value = "";
    }
  }

  async function ingestAttestation() {
    if (!offerId) return;
    await execute("attestation", async () => {
      const signedAttestation = parseObject(
        attestationText,
        "signed attestation",
      );
      await apiFetch(
        `/transparency-witnessing/checkpoint-offers/${offerId}/attestations`,
        {
          method: "POST",
          body: JSON.stringify({
            signed_attestation: signedAttestation,
            actor: "platform.admin",
          }),
        },
      );
      setAttestationText("");
      setAttestationFilename("");
      setMessage("Witness signature verified and attached to the checkpoint.");
    });
  }

  async function exportGossip() {
    if (!offerId || !sourceRegion.trim()) return;
    await execute("export", async () => {
      const gossip = await apiFetch<Record<string, unknown>>(
        `/transparency-witnessing/checkpoint-offers/${offerId}/gossip?source_region=${encodeURIComponent(sourceRegion.trim())}`,
      );
      downloadJson(gossip, `icheck-transparency-gossip-${offerId}.json`);
      setMessage("Quorum-backed gossip document exported.");
    });
  }

  async function ingestGossip() {
    if (!gossipReason.trim()) return;
    await execute("gossip", async () => {
      const gossip = parseObject(gossipText, "gossip");
      const observation = await apiFetch<Observation>(
        "/transparency-witnessing/gossip",
        {
          method: "POST",
          body: JSON.stringify({
            gossip,
            reason: gossipReason.trim(),
            actor: "platform.admin",
          }),
        },
      );
      setGossipText("");
      setGossipFilename("");
      setGossipReason("");
      setMessage(
        observation.current_status === "fork"
          ? "Fork evidence persisted. Treat this as a security incident."
          : `Gossip verified as ${observation.current_status}.`,
      );
    });
  }

  return (
    <main className="min-h-screen bg-[#eef0f5] text-[#253044]">
      <header className="border-b border-[#d8dbe0] bg-white">
        <div className="mx-auto flex min-h-16 max-w-[1400px] items-center gap-3 px-5">
          <Link
            href="/studio/catalog/transparency"
            className="rounded-md p-2 text-[#59677b] hover:bg-[#eef0f5]"
            aria-label="Back to transparency"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-[#171c2a] text-white">
            <Eye className="h-4 w-4" />
          </span>
          <div>
            <h1 className="text-sm font-semibold">External witnesses</h1>
            <p className="text-xs text-muted-foreground">
              Quorum-signed checkpoints and cross-region fork detection
            </p>
          </div>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/trust" className="ml-auto">Organization trust</Link>
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            disabled={busy !== null}
            onClick={() => void load()}
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
        </div>
      </header>

      <div className="mx-auto max-w-[1400px] space-y-6 px-5 py-6">
        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-xs text-red-700">
            {error}
          </div>
        )}
        {message && (
          <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-xs text-emerald-700">
            {message}
          </div>
        )}

        <section className="grid gap-4 md:grid-cols-3">
          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-sm">Acceptance policy</CardTitle>
              <CardDescription>
                Live quorum and maximum signature lifetime.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <Input
                  type="number"
                  min={1}
                  max={16}
                  value={quorum}
                  onChange={(event) => setQuorum(event.target.value)}
                  aria-label="Required quorum"
                />
                <Input
                  type="number"
                  min={1}
                  max={720}
                  value={maxAge}
                  onChange={(event) => setMaxAge(event.target.value)}
                  aria-label="Maximum attestation age hours"
                />
              </div>
              <Button
                className="w-full"
                disabled={busy !== null}
                onClick={() => void updatePolicy()}
              >
                {busy === "policy" && <Loader2 className="animate-spin" />}
                Save policy
              </Button>
              <p className="text-[10px] text-muted-foreground">
                Updated by {policy?.updated_by ?? "—"}
              </p>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-sm">Pin witness key</CardTitle>
              <CardDescription>
                Store only the independent witness public key.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <Input
                placeholder="witness-east-key"
                value={keyName}
                onChange={(event) => setKeyName(event.target.value)}
              />
              <Textarea
                className="min-h-20 font-mono text-[10px]"
                placeholder="-----BEGIN PUBLIC KEY-----"
                value={keyPem}
                onChange={(event) => setKeyPem(event.target.value)}
              />
              <Button
                variant="outline"
                className="w-full gap-2"
                disabled={busy !== null || !keyName.trim() || !keyPem.trim()}
                onClick={() => void pinWitnessKey()}
              >
                <KeyRound className="h-3.5 w-3.5" /> Pin public key
              </Button>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-sm">Register witness</CardTitle>
              <CardDescription>
                Bind one stable identity and region to one key.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <Input
                placeholder="East independent witness"
                value={witnessName}
                onChange={(event) => setWitnessName(event.target.value)}
              />
              <div className="grid grid-cols-2 gap-2">
                <Input
                  placeholder="witness-east-1"
                  value={externalWitnessId}
                  onChange={(event) => setExternalWitnessId(event.target.value)}
                />
                <Input
                  placeholder="us-east"
                  value={region}
                  onChange={(event) => setRegion(event.target.value)}
                />
              </div>
              <NativeSelect aria-label="Trusted signing key"
                value={trustKeyId}
                onChange={(event) => setTrustKeyId(event.target.value)}
              >
                <NativeSelectOption value="">Select witness key</NativeSelectOption>
                {witnessKeys.map((key) => (
                  <NativeSelectOption key={key.id} value={key.id}>
                    {key.name} · {shortHash(key.fingerprint_sha256)}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
              <Button
                className="w-full"
                disabled={busy !== null || !trustKeyId}
                onClick={() => void registerWitness()}
              >
                Register witness
              </Button>
            </CardContent>
          </Card>
        </section>

        <Card className="border-[#d8dbe0] shadow-none">
          <CardHeader>
            <CardTitle className="text-base">Witness registry</CardTitle>
            <CardDescription>
              Disabled witnesses and unusable keys stop counting immediately.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-2">
            {witnesses.length === 0 ? (
              <p className="text-sm text-muted-foreground">No witnesses registered.</p>
            ) : witnesses.map((witness) => (
              <div
                key={witness.id}
                className="flex items-center justify-between gap-3 rounded-lg border border-[#d8dbe0] bg-white p-4"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-semibold">{witness.name}</p>
                    <Badge variant={witness.enabled ? "default" : "outline"}>
                      {witness.enabled ? "enabled" : "disabled"}
                    </Badge>
                  </div>
                  <p className="mt-1 text-[10px] text-muted-foreground">
                    {witness.witness_id} · {witness.region} ·{" "}
                    {shortHash(witness.key_fingerprint_sha256)}
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy !== null}
                  onClick={() => void toggleWitness(witness)}
                >
                  <Power className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>

        <section className="grid gap-4 lg:grid-cols-2">
          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-base">Publish checkpoint</CardTitle>
              <CardDescription>
                Export a canonical statement for signing outside this control
                plane.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-[120px_1fr] gap-2">
                <Input
                  type="number"
                  min={1}
                  max={168}
                  value={validityHours}
                  onChange={(event) => setValidityHours(event.target.value)}
                  aria-label="Checkpoint validity hours"
                />
                <Input
                  placeholder="Reason for checkpoint publication"
                  value={offerReason}
                  onChange={(event) => setOfferReason(event.target.value)}
                />
              </div>
              <Button
                className="w-full gap-2"
                disabled={busy !== null || !offerReason.trim()}
                onClick={() => void createOffer()}
              >
                <FileSignature className="h-3.5 w-3.5" /> Create statement
              </Button>
              <div className="max-h-72 space-y-2 overflow-auto">
                {offers.map((offer) => (
                  <div
                    key={offer.id}
                    className="rounded-lg border border-[#d8dbe0] bg-white p-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <p className="font-mono text-[10px]">
                        seq {offer.sequence} · epoch {offer.epoch}
                      </p>
                      <Badge
                        variant={offer.quorum_satisfied ? "default" : "outline"}
                      >
                        {offer.attestation_count}/{offer.required_quorum}
                      </Badge>
                    </div>
                    <p className="mt-2 font-mono text-[9px] text-muted-foreground">
                      log {offer.log_id} · head {shortHash(offer.head_digest_sha256)}
                    </p>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="mt-2 gap-2"
                      onClick={() => downloadJson(
                        offer.statement,
                        `icheck-checkpoint-${offer.sequence}.json`,
                      )}
                    >
                      <Download className="h-3.5 w-3.5" /> Statement
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-base">Ingest witness signature</CardTitle>
              <CardDescription>
                Verify identity, purpose, signature, checkpoint binding, and
                lifetime.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <NativeSelect aria-label="Witness checkpoint"
                value={offerId}
                onChange={(event) => setOfferId(event.target.value)}
              >
                <NativeSelectOption value="">Select checkpoint</NativeSelectOption>
                {offers.map((offer) => (
                  <NativeSelectOption key={offer.id} value={offer.id}>
                    sequence {offer.sequence} · {offer.attestation_count}/
                    {offer.required_quorum}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
              <label className="flex cursor-pointer items-center justify-center gap-2 rounded-md border border-dashed border-[#aeb6c2] p-4 text-xs">
                <Upload className="h-4 w-4" />
                {attestationFilename || "Choose signed attestation JSON"}
                <input
                  type="file"
                  accept="application/json,.json"
                  className="hidden"
                  onChange={(event) => void readJsonFile(
                    event,
                    setAttestationText,
                    setAttestationFilename,
                  )}
                />
              </label>
              <Textarea
                className="min-h-28 font-mono text-[10px]"
                placeholder="Or paste signed attestation JSON"
                value={attestationText}
                onChange={(event) => setAttestationText(event.target.value)}
              />
              <Button
                className="w-full"
                disabled={busy !== null || !offerId || !attestationText.trim()}
                onClick={() => void ingestAttestation()}
              >
                Verify and attach
              </Button>
              <div className="grid grid-cols-[1fr_140px] gap-2 border-t pt-3">
                <Input
                  placeholder="Source region"
                  value={sourceRegion}
                  onChange={(event) => setSourceRegion(event.target.value)}
                />
                <Button
                  variant="outline"
                  className="gap-2"
                  disabled={busy !== null || !offerId}
                  onClick={() => void exportGossip()}
                >
                  <Download className="h-3.5 w-3.5" /> Gossip
                </Button>
              </div>
            </CardContent>
          </Card>
        </section>

        <section className="grid gap-4 lg:grid-cols-[420px_1fr]">
          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-base">Compare remote gossip</CardTitle>
              <CardDescription>
                Import a quorum-backed regional checkpoint. Fork evidence is
                durable.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <label className="flex cursor-pointer items-center justify-center gap-2 rounded-md border border-dashed border-[#aeb6c2] p-4 text-xs">
                <Upload className="h-4 w-4" />
                {gossipFilename || "Choose gossip JSON"}
                <input
                  type="file"
                  accept="application/json,.json"
                  className="hidden"
                  onChange={(event) => void readJsonFile(
                    event,
                    setGossipText,
                    setGossipFilename,
                  )}
                />
              </label>
              <Textarea
                className="min-h-32 font-mono text-[10px]"
                placeholder="Or paste gossip JSON"
                value={gossipText}
                onChange={(event) => setGossipText(event.target.value)}
              />
              <Input
                placeholder="Reason for cross-region comparison"
                value={gossipReason}
                onChange={(event) => setGossipReason(event.target.value)}
              />
              <Button
                className="w-full gap-2"
                disabled={
                  busy !== null
                  || !gossipText.trim()
                  || !gossipReason.trim()
                }
                onClick={() => void ingestGossip()}
              >
                <Network className="h-3.5 w-3.5" /> Verify gossip
              </Button>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-base">Regional observations</CardTitle>
              <CardDescription>
                Initial status is immutable; current status is recalculated
                against the local chain head.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {observations.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No remote checkpoints compared.
                </p>
              ) : observations.map((observation) => (
                <div
                  key={observation.id}
                  className={cn(
                    "rounded-lg border bg-white p-4",
                    observation.current_status === "fork"
                      ? "border-red-300"
                      : "border-[#d8dbe0]",
                  )}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3">
                      {observation.current_status === "fork" ? (
                        <ShieldAlert className="h-5 w-5 text-red-600" />
                      ) : (
                        <CheckCircle2 className="h-5 w-5 text-emerald-600" />
                      )}
                      <div>
                        <p className="text-sm font-semibold">
                          {observation.source_region}
                        </p>
                        <p className="mt-1 text-[10px] text-muted-foreground">
                          sequence {observation.sequence} ·{" "}
                          {observation.witness_count} witnesses ·{" "}
                          {new Date(observation.received_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Badge variant="outline">
                        initial {observation.initial_status}
                      </Badge>
                      <Badge
                        variant={
                          observation.current_status === "fork"
                            ? "destructive"
                            : "default"
                        }
                      >
                        {observation.current_status}
                      </Badge>
                    </div>
                  </div>
                  <p className="mt-3 font-mono text-[9px] text-muted-foreground">
                    log {observation.log_id} · head{" "}
                    {shortHash(observation.head_digest_sha256)} · document{" "}
                    {shortHash(observation.document_digest_sha256)}
                  </p>
                </div>
              ))}
            </CardContent>
          </Card>
        </section>
      </div>
    </main>
  );
}
