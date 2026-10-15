"use client";

import Link from "next/link";
import { ChangeEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  ArrowRightLeft,
  CheckCircle2,
  Download,
  FileSignature,
  KeyRound,
  Loader2,
  Power,
  RefreshCw,
  ShieldCheck,
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

type Stage = "development" | "test" | "staging" | "production";
type PublicationMode = "disabled" | "manual";

type TrustKey = {
  id: string;
  name: string;
  fingerprint_sha256: string;
  enabled: boolean;
  purposes: string[];
};

type Policy = {
  id: string;
  local_environment_id: string;
  local_stage: Stage;
  required_source_stage: Stage;
  max_attestation_age_hours: number;
  publication_mode: PublicationMode;
  require_distinct_publisher: boolean;
  updated_by: string;
  updated_at: string;
};

type Source = {
  id: string;
  name: string;
  organization_id: string;
  environment_id: string;
  source_stage: Stage;
  trust_key_id: string;
  key_fingerprint_sha256: string;
  enabled: boolean;
  latest_sequence: number;
  latest_statement_digest_sha256: string | null;
};

type KeyRotation = {
  id: string;
  source_id: string;
  from_key_fingerprint_sha256: string;
  to_key_fingerprint_sha256: string;
  promotion_sequence: number;
  rotated_by: string;
  rotated_at: string;
};

type Witness = {id: string; name: string; witness_id: string; enabled: boolean; key_fingerprint_sha256: string};
type SourceWitnessPolicy = {required_quorum: number; witness_ids: string[]; max_attestation_age_hours: number};
type CheckpointBinding = {source_id: string; log_id: string; epoch: number; updated_by: string};

type Installation = {
  id: string;
  pack_name: string;
  pack_version: string;
  pack_digest_sha256: string;
  lifecycle_status: "installed" | "uninstalled";
  artifacts: Array<{ artifact_version_id: string }>;
};

type Preview = {
  source_id: string;
  source_environment_id: string;
  target_environment_id: string;
  target_stage: Stage;
  promotion_sequence: number;
  installation_id: string | null;
  pack_name: string;
  pack_version: string;
  pack_digest_sha256: string;
  artifact_count: number;
  source_transparency_log_id: string;
  source_transparency_epoch: number;
  source_transparency_sequence: number;
  source_transparency_head_sha256: string;
  promotable: boolean;
  already_accepted: boolean;
  existing_receipt_id: string | null;
  blockers: string[];
  source_witness_count: number;
  required_source_witness_quorum: number;
};

type Receipt = {
  id: string;
  source_id: string;
  installation_id: string;
  source_environment_id: string;
  source_stage: Stage;
  target_environment_id: string;
  target_stage: Stage;
  promotion_sequence: number;
  pack_name: string;
  pack_version: string;
  pack_digest_sha256: string;
  artifact_count: number;
  statement_digest_sha256: string;
  source_transparency_log_id: string;
  source_transparency_sequence: number;
  validation_evidence_digest_sha256: string;
  accepted_by: string;
  accepted_at: string;
};

type Publication = {
  id: string;
  receipt_id: string;
  publication_digest_sha256: string;
  artifact_count: number;
  newly_published_count: number;
  published_by: string;
  published_at: string;
};

type PublicationPreview = {
  receipt_id: string;
  installation_id: string;
  eligible: boolean;
  already_published: boolean;
  existing_publication_id: string | null;
  artifact_version_ids: string[];
  candidate_artifact_version_ids: string[];
  already_published_version_ids: string[];
  reused_version_ids: string[];
  blockers: string[];
};

const stages: Stage[] = ["development", "test", "staging", "production"];

function shortHash(value: string | null) {
  return value ? `${value.slice(0, 12)}…` : "—";
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

function parseObject(value: string): Record<string, unknown> {
  if (!value.trim()) throw new Error("Select or paste a signed attestation");
  const document = JSON.parse(value) as Record<string, unknown>;
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("Signed promotion attestation must be a JSON object");
  }
  return document;
}

export default function CapabilityPromotionsPage() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [keys, setKeys] = useState<TrustKey[]>([]);
  const [sources, setSources] = useState<Source[]>([]);
  const [keyRotations, setKeyRotations] = useState<KeyRotation[]>([]);
  const [witnesses, setWitnesses] = useState<Witness[]>([]);
  const [witnessIds, setWitnessIds] = useState<string[]>([]);
  const [witnessQuorum, setWitnessQuorum] = useState("0");
  const [witnessAge, setWitnessAge] = useState("168");
  const [witnessReason, setWitnessReason] = useState("");
  const [checkpointBindings, setCheckpointBindings] = useState<CheckpointBinding[]>([]);
  const [checkpointSourceId, setCheckpointSourceId] = useState("");
  const [checkpointLogId, setCheckpointLogId] = useState("");
  const [checkpointEpoch, setCheckpointEpoch] = useState("1");
  const [checkpointReason, setCheckpointReason] = useState("");
  const [checkpointEvidenceText, setCheckpointEvidenceText] = useState("");
  const [rotationSourceId, setRotationSourceId] = useState("");
  const [rotationKeyId, setRotationKeyId] = useState("");
  const [rotationReason, setRotationReason] = useState("");
  const [rotationValidity, setRotationValidity] = useState("1");
  const [rotationText, setRotationText] = useState("");
  const [installations, setInstallations] = useState<Installation[]>([]);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [publications, setPublications] = useState<Publication[]>([]);
  const [localEnvironmentId, setLocalEnvironmentId] = useState("");
  const [localStage, setLocalStage] = useState<Stage>("production");
  const [requiredSourceStage, setRequiredSourceStage] =
    useState<Stage>("staging");
  const [maxAge, setMaxAge] = useState("24");
  const [publicationMode, setPublicationMode] =
    useState<PublicationMode>("disabled");
  const [requireDistinctPublisher, setRequireDistinctPublisher] =
    useState(true);
  const [keyName, setKeyName] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [sourceName, setSourceName] = useState("");
  const [organizationId, setOrganizationId] = useState("");
  const [sourceEnvironmentId, setSourceEnvironmentId] = useState("");
  const [sourceStage, setSourceStage] = useState<Stage>("staging");
  const [trustKeyId, setTrustKeyId] = useState("");
  const [installationId, setInstallationId] = useState("");
  const [targetEnvironmentId, setTargetEnvironmentId] = useState("");
  const [targetStage, setTargetStage] = useState<Stage>("production");
  const [promotionSequence, setPromotionSequence] = useState("1");
  const [evidenceDigest, setEvidenceDigest] = useState("");
  const [validityHours, setValidityHours] = useState("24");
  const [attestationText, setAttestationText] = useState("");
  const [attestationFilename, setAttestationFilename] = useState("");
  const [acceptReason, setAcceptReason] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [publicationPreviews, setPublicationPreviews] = useState<
    Record<string, PublicationPreview>
  >({});
  const [publicationReasons, setPublicationReasons] = useState<
    Record<string, string>
  >({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [
        policyRow,
        keyRows,
        sourceRows,
        installationRows,
        receiptRows,
        publicationRows,
        rotationRows,
        witnessRows, witnessPolicyRow, bindingRows,
      ] =
        await Promise.all([
          apiFetch<Policy | null>("/capability-promotions/policy"),
          apiFetch<TrustKey[]>("/artifact-trust-keys"),
          apiFetch<Source[]>("/capability-promotions/sources?limit=500"),
          apiFetch<Installation[]>("/capability-packs?limit=500"),
          apiFetch<Receipt[]>("/capability-promotions/receipts?limit=500"),
          apiFetch<Publication[]>(
            "/capability-promotions/publications?limit=500",
          ),
          apiFetch<KeyRotation[]>("/capability-promotions/key-rotations?limit=500"),
          apiFetch<Witness[]>("/transparency-witnessing/witnesses?limit=500"),
          apiFetch<SourceWitnessPolicy>("/capability-promotions/source-witness-policy"),
          apiFetch<CheckpointBinding[]>("/capability-promotions/source-checkpoint-bindings"),
        ]);
      setPolicy(policyRow);
      setKeys(keyRows);
      setSources(sourceRows);
      setInstallations(installationRows);
      setReceipts(receiptRows);
      setPublications(publicationRows);
      setKeyRotations(rotationRows);
      setWitnesses(witnessRows);
      setWitnessIds(witnessPolicyRow.witness_ids);
      setWitnessQuorum(String(witnessPolicyRow.required_quorum));
      setWitnessAge(String(witnessPolicyRow.max_attestation_age_hours));
      setCheckpointBindings(bindingRows);
      if (policyRow) {
        setLocalEnvironmentId(policyRow.local_environment_id);
        setLocalStage(policyRow.local_stage);
        setRequiredSourceStage(policyRow.required_source_stage);
        setMaxAge(String(policyRow.max_attestation_age_hours));
        setPublicationMode(policyRow.publication_mode);
        setRequireDistinctPublisher(
          policyRow.require_distinct_publisher,
        );
        setTargetEnvironmentId((current) => (
          current || policyRow.local_environment_id
        ));
        setTargetStage((current) => current || policyRow.local_stage);
      }
      const eligibleKeys = keyRows.filter(
        (key) => key.enabled && key.purposes.includes("environment_promotion"),
      );
      const eligiblePacks = installationRows.filter(
        (item) => item.lifecycle_status === "installed",
      );
      setTrustKeyId((current) => current || eligibleKeys[0]?.id || "");
      setInstallationId(
        (current) => current || eligiblePacks[0]?.id || "",
      );
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to load capability promotions",
      );
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const promotionKeys = useMemo(
    () => keys.filter(
      (key) => key.enabled && key.purposes.includes("environment_promotion"),
    ),
    [keys],
  );
  const installedPacks = installations.filter(
    (item) => item.lifecycle_status === "installed",
  );
  const rotationSource = sources.find((source) => source.id === rotationSourceId);
  const validRotationSelection = Boolean(policy && rotationSource?.enabled && rotationKeyId
    && rotationKeyId !== rotationSource.trust_key_id && rotationReason.trim().length >= 3);
  const publicationByReceipt = useMemo(
    () => new Map(publications.map((item) => [item.receipt_id, item])),
    [publications],
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

  async function savePolicy() {
    if (!localEnvironmentId.trim()) return;
    await execute("policy", async () => {
      await apiFetch<Policy>("/capability-promotions/policy", {
        method: "PUT",
        body: JSON.stringify({
          local_environment_id: localEnvironmentId.trim(),
          local_stage: localStage,
          required_source_stage: requiredSourceStage,
          max_attestation_age_hours: Number(maxAge),
          publication_mode: publicationMode,
          require_distinct_publisher: requireDistinctPublisher,
          reason: "Configure the local capability promotion boundary.",
          actor: "platform.admin",
        }),
      });
      setMessage("Promotion boundary and publication policy saved.");
    });
  }

  const validWitnessPolicy = Boolean(policy && witnessReason.trim().length >= 3
    && Number.isInteger(Number(witnessQuorum)) && Number(witnessQuorum) >= 0 && Number(witnessQuorum) <= 16
    && Number(witnessQuorum) <= witnessIds.length && Number.isInteger(Number(witnessAge))
    && Number(witnessAge) >= 1 && Number(witnessAge) <= 720);

  async function saveWitnessPolicy() {
    if (!validWitnessPolicy) return;
    await execute("witness-policy", async () => {
      await apiFetch("/capability-promotions/source-witness-policy", {method: "PUT", body: JSON.stringify({
        required_quorum: Number(witnessQuorum), witness_ids: witnessIds, max_attestation_age_hours: Number(witnessAge),
        reason: witnessReason.trim(), actor: "platform.admin"})});
      setMessage("Source checkpoint witness policy saved. New acceptance and publication use current authority.");
    });
  }

  async function saveCheckpointBinding() {
    if (!checkpointSourceId || !checkpointLogId.trim() || checkpointReason.trim().length < 3) return;
    await execute("checkpoint-binding", async () => {
      await apiFetch(`/capability-promotions/sources/${checkpointSourceId}/checkpoint-binding`, {method: "PUT", body: JSON.stringify({
        log_id: checkpointLogId.trim(), epoch: Number(checkpointEpoch), reason: checkpointReason.trim(), actor: "platform.admin"})});
      setMessage("Reviewed source checkpoint binding saved. The accepted promotion sequence is unchanged.");
    });
  }

  function attachCheckpointEvidence() {
    try {
      const signed = parseObject(attestationText);
      const evidence = parseObject(checkpointEvidenceText);
      if (signed.format_version !== "icheck.capability-promotion-attestation.signed/v1"
        || evidence.format_version !== "icheck.capability-transparency-gossip/v1") {
        throw new Error("Use a signed promotion envelope and the exported source checkpoint gossip document");
      }
      const text = JSON.stringify({...signed, source_checkpoint_evidence: evidence}, null, 2);
      if (new TextEncoder().encode(text).length > 262_144) throw new Error("Combined promotion document exceeds 256 KiB");
      setAttestationText(text);
      setPreview(null);
      setError(null);
      setMessage("Checkpoint evidence attached. Target verification is still required; existing receipts cannot be amended.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to attach source checkpoint evidence");
    }
  }

  async function pinKey() {
    if (!keyName.trim() || !keyPem.trim()) return;
    await execute("key", async () => {
      const key = await apiFetch<TrustKey>("/artifact-trust-keys", {
        method: "POST",
        body: JSON.stringify({
          name: keyName.trim(),
          public_key_pem: keyPem.trim(),
          purposes: ["environment_promotion"],
          created_by: "platform.admin",
        }),
      });
      setTrustKeyId(key.id);
      setKeyName("");
      setKeyPem("");
      setMessage("Promotion authority public key pinned.");
    });
  }

  async function registerSource() {
    if (
      !sourceName.trim()
      || !organizationId.trim()
      || !sourceEnvironmentId.trim()
      || !trustKeyId
    ) return;
    await execute("source", async () => {
      await apiFetch<Source>("/capability-promotions/sources", {
        method: "POST",
        body: JSON.stringify({
          name: sourceName.trim(),
          organization_id: organizationId.trim(),
          environment_id: sourceEnvironmentId.trim(),
          source_stage: sourceStage,
          trust_key_id: trustKeyId,
          created_by: "platform.admin",
        }),
      });
      setSourceName("");
      setSourceEnvironmentId("");
      setMessage("Promotion source registered with exact environment identity.");
    });
  }

  async function toggleSource(source: Source) {
    await execute(`source-${source.id}`, async () => {
      await apiFetch(
        `/capability-promotions/sources/${source.id}/state`,
        {
          method: "POST",
          body: JSON.stringify({
            enabled: !source.enabled,
            reason: `${source.enabled ? "Disable" : "Enable"} source from Studio.`,
            actor: "platform.admin",
          }),
        },
      );
      setMessage(
        source.enabled
          ? "Promotion source disabled immediately."
          : "Promotion source re-enabled after key validation.",
      );
    });
  }

  async function exportRotationStatement() {
    if (!validRotationSelection) return;
    await execute("rotation-statement", async () => {
      const statement = await apiFetch<Record<string, unknown>>(
        `/capability-promotions/sources/${rotationSourceId}/key-rotation-statements`, {
          method: "POST", body: JSON.stringify({new_trust_key_id: rotationKeyId,
            validity_hours: Number(rotationValidity), reason: rotationReason.trim(), actor: "platform.admin"}),
        });
      downloadJson(statement, "icheck-promotion-key-rotation-statement.json");
      setMessage("Statement exported. Both current and successor keys must sign it outside iCheck.");
    });
  }

  async function readRotationFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      if (file.size > 65_536) throw new Error("Rotation document exceeds 64 KiB");
      const text = await file.text();
      if (parseObject(text).format_version !== "icheck.capability-promotion-key-rotation.signed/v1") {
        throw new Error("Select a dual-signed promotion key rotation document");
      }
      setRotationText(text);
      setError(null);
    } catch (cause) {
      setRotationText("");
      setError(cause instanceof Error ? cause.message : "Unable to read rotation document");
    } finally {
      event.target.value = "";
    }
  }

  async function rotateKey() {
    if (!validRotationSelection || !rotationText.trim()) return;
    await execute("rotation", async () => {
      if (new TextEncoder().encode(rotationText).length > 65_536) throw new Error("Rotation document exceeds 64 KiB");
      const signed = parseObject(rotationText);
      if (signed.format_version !== "icheck.capability-promotion-key-rotation.signed/v1") {
        throw new Error("Select a dual-signed promotion key rotation document");
      }
      const result = await apiFetch<KeyRotation>(`/capability-promotions/sources/${rotationSourceId}/rotate-key`, {
        method: "POST", body: JSON.stringify({new_trust_key_id: rotationKeyId, signed_rotation: signed,
          reason: rotationReason.trim(), actor: "platform.admin"}),
      });
      setRotationText("");
      setRotationKeyId("");
      setMessage(`Recorded handover ${shortHash(result.id)} by ${result.rotated_by}. History does not grant new authority.`);
    });
  }

  async function createStatement() {
    if (
      !installationId
      || !organizationId.trim()
      || !targetEnvironmentId.trim()
      || evidenceDigest.length !== 64
    ) return;
    await execute("statement", async () => {
      const statement = await apiFetch<Record<string, unknown>>(
        "/capability-promotions/statements",
        {
          method: "POST",
          body: JSON.stringify({
            installation_id: installationId,
            organization_id: organizationId.trim(),
            target_environment_id: targetEnvironmentId.trim(),
            target_stage: targetStage,
            promotion_sequence: Number(promotionSequence),
            validation_evidence_digest_sha256: evidenceDigest,
            validity_hours: Number(validityHours),
            actor: "release.operator",
          }),
        },
      );
      downloadJson(
        statement,
        `icheck-promotion-statement-${promotionSequence}.json`,
      );
      setMessage(
        "Unsigned statement exported. Sign it outside iCheck with the source promotion key.",
      );
    });
  }

  async function readAttestationFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      setAttestationText(await file.text());
      setAttestationFilename(file.name);
      setPreview(null);
      setError(null);
    } catch {
      setError("Unable to read the selected attestation file");
    } finally {
      event.target.value = "";
    }
  }

  async function previewPromotion() {
    await execute("preview", async () => {
      const signedAttestation = parseObject(attestationText);
      setPreview(
        await apiFetch<Preview>("/capability-promotions/preview", {
          method: "POST",
          body: JSON.stringify({ signed_attestation: signedAttestation }),
        }),
      );
      setMessage("Signature and target-side state revalidation completed.");
    });
  }

  async function acceptPromotion() {
    if (!preview?.promotable || !acceptReason.trim()) return;
    await execute("accept", async () => {
      const signedAttestation = parseObject(attestationText);
      await apiFetch<Receipt>("/capability-promotions/accept", {
        method: "POST",
        body: JSON.stringify({
          signed_attestation: signedAttestation,
          reason: acceptReason.trim(),
          actor: "platform.admin",
        }),
      });
      setPreview(null);
      setAttestationText("");
      setAttestationFilename("");
      setAcceptReason("");
      setMessage(
        "Promotion receipt accepted. Publication and activation remain separate.",
      );
    });
  }

  async function exportReceipt(receipt: Receipt) {
    await execute(`export-${receipt.id}`, async () => {
      const document = await apiFetch<Record<string, unknown>>(
        `/capability-promotions/receipts/${receipt.id}/export`,
      );
      downloadJson(
        document,
        `icheck-promotion-receipt-${receipt.promotion_sequence}.json`,
      );
      setMessage("Exact signed promotion envelope exported.");
    });
  }

  async function previewPublication(receipt: Receipt) {
    const reason = publicationReasons[receipt.id]?.trim();
    if (!reason) return;
    await execute(`publication-preview-${receipt.id}`, async () => {
      const result = await apiFetch<PublicationPreview>(
        `/capability-promotions/receipts/${receipt.id}/publication-preview`,
        {
          method: "POST",
          body: JSON.stringify({
            reason,
            actor: "platform.publisher",
          }),
        },
      );
      setPublicationPreviews((current) => ({
        ...current,
        [receipt.id]: result,
      }));
      setMessage("Current publication policy and Artifact state evaluated.");
    });
  }

  async function publishReceipt(receipt: Receipt) {
    const reason = publicationReasons[receipt.id]?.trim();
    const previewRow = publicationPreviews[receipt.id];
    if (!reason || !previewRow?.eligible) return;
    await execute(`publish-${receipt.id}`, async () => {
      await apiFetch<Publication>(
        `/capability-promotions/receipts/${receipt.id}/publish`,
        {
          method: "POST",
          body: JSON.stringify({
            reason,
            actor: "platform.publisher",
          }),
        },
      );
      setPublicationPreviews((current) => {
        const next = { ...current };
        delete next[receipt.id];
        return next;
      });
      setMessage(
        "Pack-owned Artifact versions published atomically; runtime activation remains separate.",
      );
    });
  }

  return (
    <main className="min-h-screen bg-[#eef0f5] text-[#253044]">
      <header className="border-b border-[#d8dbe0] bg-white">
        <div className="mx-auto flex min-h-16 max-w-[1500px] flex-wrap items-center gap-3 px-5 py-3">
          <Link
            href="/studio/catalog"
            className="rounded-md p-2 text-[#59677b] hover:bg-[#eef0f5]"
            aria-label="Back to catalog"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[#171c2a] text-white">
            <ArrowRightLeft className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1 basis-[200px]">
            <h1 className="text-sm font-semibold">Environment promotion</h1>
            <p className="text-xs text-muted-foreground">
              Source evidence → signed attestation → target revalidation
            </p>
          </div>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/packs" className="sm:ml-auto">Organization packs</Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/trust">Organization trust</Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/promotions/recovery">Emergency recovery</Link>
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

      <div className="mx-auto max-w-[1500px] space-y-6 px-5 py-6">
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

        <section className="grid gap-4 lg:grid-cols-3">
          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-sm">Local boundary</CardTitle>
              <CardDescription>
                Identity becomes immutable after the first accepted receipt.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <Input
                placeholder="production-us"
                value={localEnvironmentId}
                onChange={(event) => setLocalEnvironmentId(event.target.value)}
              />
              <div className="grid grid-cols-2 gap-2">
                <NativeSelect aria-label="Local promotion stage"
                  value={localStage}
                  onChange={(event) => setLocalStage(event.target.value as Stage)}
                >
                  {stages.map((stage) => (
                    <NativeSelectOption key={stage} value={stage}>
                      local: {stage}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
                <NativeSelect aria-label="Required source promotion stage"
                  value={requiredSourceStage}
                  onChange={(event) => (
                    setRequiredSourceStage(event.target.value as Stage)
                  )}
                >
                  {stages.map((stage) => (
                    <NativeSelectOption key={stage} value={stage}>
                      source: {stage}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </div>
              <Input
                type="number"
                min={1}
                max={168}
                value={maxAge}
                onChange={(event) => setMaxAge(event.target.value)}
                aria-label="Maximum attestation age hours"
              />
              <NativeSelect aria-label="Promotion publication mode"
                value={publicationMode}
                onChange={(event) => (
                  setPublicationMode(event.target.value as PublicationMode)
                )}
              >
                <NativeSelectOption value="disabled">
                  publication disabled
                </NativeSelectOption>
                <NativeSelectOption value="manual">
                  manual atomic publication
                </NativeSelectOption>
              </NativeSelect>
              <label className="flex items-center gap-2 rounded-md border border-[#d8dbe0] px-3 py-2 text-xs text-[#59677b]">
                <input
                  type="checkbox"
                  checked={requireDistinctPublisher}
                  onChange={(event) => (
                    setRequireDistinctPublisher(event.target.checked)
                  )}
                />
                Require a publisher distinct from the receipt acceptor
              </label>
              <Button
                className="w-full"
                disabled={busy !== null || !localEnvironmentId.trim()}
                onClick={() => void savePolicy()}
              >
                Save boundary
              </Button>
              <p className="text-[10px] text-muted-foreground">
                {policy
                  ? `${policy.local_environment_id} · ${policy.local_stage} · publication ${policy.publication_mode}`
                  : "Not configured"}
              </p>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-sm">Pin promotion key</CardTitle>
              <CardDescription>
                Public key only; signing remains outside the control plane.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <Input
                placeholder="staging-promotion-key"
                value={keyName}
                onChange={(event) => setKeyName(event.target.value)}
              />
              <Textarea
                className="min-h-24 font-mono text-[10px]"
                placeholder="-----BEGIN PUBLIC KEY-----"
                value={keyPem}
                onChange={(event) => setKeyPem(event.target.value)}
              />
              <Button
                variant="outline"
                className="w-full gap-2"
                disabled={busy !== null || !keyName.trim() || !keyPem.trim()}
                onClick={() => void pinKey()}
              >
                <KeyRound className="h-3.5 w-3.5" /> Pin public key
              </Button>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-sm">Register source</CardTitle>
              <CardDescription>
                Bind organization, environment, stage, and one exact key.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <Input
                placeholder="US staging"
                value={sourceName}
                onChange={(event) => setSourceName(event.target.value)}
              />
              <div className="grid grid-cols-2 gap-2">
                <Input
                  placeholder="organization-id"
                  value={organizationId}
                  onChange={(event) => setOrganizationId(event.target.value)}
                />
                <Input
                  placeholder="staging-us"
                  value={sourceEnvironmentId}
                  onChange={(event) => setSourceEnvironmentId(event.target.value)}
                />
              </div>
              <NativeSelect aria-label="Remote source stage"
                value={sourceStage}
                onChange={(event) => setSourceStage(event.target.value as Stage)}
              >
                {stages.map((stage) => (
                  <NativeSelectOption key={stage} value={stage}>
                    {stage}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
              <NativeSelect aria-label="Trusted signing key"
                value={trustKeyId}
                onChange={(event) => setTrustKeyId(event.target.value)}
              >
                <NativeSelectOption value="">Select promotion key</NativeSelectOption>
                {promotionKeys.map((key) => (
                  <NativeSelectOption key={key.id} value={key.id}>
                    {key.name} · {shortHash(key.fingerprint_sha256)}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
              <Button
                className="w-full"
                disabled={busy !== null || !trustKeyId}
                onClick={() => void registerSource()}
              >
                Register source
              </Button>
            </CardContent>
          </Card>
        </section>

        <Card className="border-[#d8dbe0] shadow-none">
          <CardHeader>
            <CardTitle className="text-base">Trusted source environments</CardTitle>
            <CardDescription>
              Sequences are contiguous per source. Disable is the immediate
              break-glass control.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {sources.length === 0 ? (
              <p className="text-sm text-muted-foreground">No sources registered.</p>
            ) : sources.map((source) => (
              <div
                key={source.id}
                className="flex items-center justify-between rounded-lg border border-[#d8dbe0] bg-white p-4"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-semibold">{source.name}</p>
                    <Badge variant={source.enabled ? "default" : "outline"}>
                      {source.enabled ? "enabled" : "disabled"}
                    </Badge>
                  </div>
                  <p className="mt-1 text-[10px] text-muted-foreground">
                    {source.environment_id} · {source.source_stage} · next{" "}
                    {source.latest_sequence + 1}
                  </p>
                  <p className="mt-1 font-mono text-[9px] text-muted-foreground">
                    {shortHash(source.key_fingerprint_sha256)}
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy !== null}
                  onClick={() => void toggleSource(source)}
                >
                  <Power className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>

        <section className="grid gap-4 xl:grid-cols-2">
          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-base">Source checkpoint witness policy</CardTitle>
              <CardDescription>Require allowlisted independent keys for new acceptance and publication.
                Zero means not required. Tightening policy can block pending receipts without matching evidence.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Link href="/studio/catalog/transparency/witnesses" className="text-xs underline">Manage independent witness pins</Link>
              <div className="grid grid-cols-2 gap-3">
                <label className="space-y-1 text-xs">Required quorum
                  <Input aria-label="Required source witness quorum" type="number" min={0} max={16} value={witnessQuorum}
                    onChange={(event) => setWitnessQuorum(event.target.value)} />
                </label>
                <label className="space-y-1 text-xs">Maximum age in hours
                  <Input aria-label="Source witness maximum age hours" type="number" min={1} max={720} value={witnessAge}
                    onChange={(event) => setWitnessAge(event.target.value)} />
                </label>
              </div>
              {witnesses.map((witness) => <label key={witness.id} className="flex items-center gap-2 text-xs">
                <input type="checkbox" aria-label={`Allow source witness ${witness.name}`} disabled={busy !== null}
                  checked={witnessIds.includes(witness.id)} onChange={(event) => setWitnessIds((current) => event.target.checked
                    ? [...current, witness.id] : current.filter((identity) => identity !== witness.id))} />
                <span>{witness.name} · {shortHash(witness.key_fingerprint_sha256)} · {witness.enabled ? "enabled" : "disabled"}</span>
              </label>)}
              {witnesses.length === 0 && <p className="text-xs text-muted-foreground">Pin independent witnesses before requiring quorum.</p>}
              <Input aria-label="Source witness policy review reason" maxLength={4000} placeholder="Why require this witness policy?"
                value={witnessReason} onChange={(event) => setWitnessReason(event.target.value)} />
              <Button disabled={busy !== null || !validWitnessPolicy} onClick={() => void saveWitnessPolicy()}>Save source witness policy</Button>
            </CardContent>
          </Card>
          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-base">Pin source checkpoint identity</CardTitle>
              <CardDescription>Review the source log ID and epoch independently. Drain unexpired unpublished receipts before changing a pin.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <NativeSelect aria-label="Checkpoint source" value={checkpointSourceId} onChange={(event) => {
                setCheckpointSourceId(event.target.value);
                const binding = checkpointBindings.find((item) => item.source_id === event.target.value);
                setCheckpointLogId(binding?.log_id || ""); setCheckpointEpoch(String(binding?.epoch || 1));
              }}>
                <NativeSelectOption value="">Select source checkpoint identity</NativeSelectOption>
                {sources.map((source) => <NativeSelectOption key={source.id} value={source.id}>{source.name}</NativeSelectOption>)}
              </NativeSelect>
              <Input aria-label="Source transparency log ID" maxLength={36} placeholder="Independently reviewed source log ID"
                value={checkpointLogId} onChange={(event) => setCheckpointLogId(event.target.value)} />
              <label className="block space-y-1 text-xs">Source log epoch
                <Input aria-label="Source transparency epoch" type="number" min={1} value={checkpointEpoch}
                  onChange={(event) => setCheckpointEpoch(event.target.value)} />
              </label>
              <Input aria-label="Source checkpoint binding review reason" maxLength={4000} placeholder="Why trust this source log and epoch?"
                value={checkpointReason} onChange={(event) => setCheckpointReason(event.target.value)} />
              <Button disabled={busy !== null || !checkpointSourceId || !checkpointLogId.trim() || checkpointReason.trim().length < 3
                || !Number.isInteger(Number(checkpointEpoch)) || Number(checkpointEpoch) < 1} onClick={() => void saveCheckpointBinding()}>Save reviewed checkpoint binding</Button>
              {checkpointBindings.map((binding) => <p key={binding.source_id} className="break-all text-xs text-[#59677b]">
                {sources.find((source) => source.id === binding.source_id)?.name || binding.source_id} · {binding.log_id} · epoch {binding.epoch} · {binding.updated_by}
              </p>)}
            </CardContent>
          </Card>
        </section>

        <Card className="border-[#d8dbe0] shadow-none">
          <CardHeader>
            <CardTitle className="text-base">Planned promotion key handover</CardTitle>
            <CardDescription>
              Publish unexpired pending receipts first. Current and successor keys must sign the same
              exported statement outside iCheck. This is not revoked-key recovery or activation.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-3 md:grid-cols-2">
              <NativeSelect aria-label="Rotation source" value={rotationSourceId} onChange={(event) => {
                setRotationSourceId(event.target.value); setRotationKeyId(""); setRotationText("");
              }}>
                <NativeSelectOption value="">Select source for handover</NativeSelectOption>
                {sources.map((source) => <NativeSelectOption key={source.id} value={source.id}>
                  {source.name} · {source.enabled ? "enabled" : "disabled"}
                </NativeSelectOption>)}
              </NativeSelect>
              <NativeSelect aria-label="Successor promotion key" value={rotationKeyId} onChange={(event) => {
                setRotationKeyId(event.target.value); setRotationText("");
              }}>
                <NativeSelectOption value="">Select a different successor key</NativeSelectOption>
                {promotionKeys.filter((key) => key.id !== rotationSource?.trust_key_id).map((key) => (
                  <NativeSelectOption key={key.id} value={key.id}>{key.name} · {shortHash(key.fingerprint_sha256)}</NativeSelectOption>
                ))}
              </NativeSelect>
            </div>
            {rotationSource && <p className="text-xs text-[#59677b]">
              {rotationSource.environment_id} · current {shortHash(rotationSource.key_fingerprint_sha256)} ·
              accepted sequence {rotationSource.latest_sequence} · head {shortHash(rotationSource.latest_statement_digest_sha256)}
            </p>}
            <div className="grid gap-3 md:grid-cols-[1fr_180px]">
              <Input aria-label="Rotation review reason" placeholder="Reviewed handover reason" value={rotationReason}
                onChange={(event) => setRotationReason(event.target.value)} />
              <Input aria-label="Rotation statement lifetime hours" type="number" min={1} max={24}
                value={rotationValidity} onChange={(event) => setRotationValidity(event.target.value)} />
            </div>
            <Button variant="outline" className="gap-2" disabled={busy !== null || !validRotationSelection
              || !Number.isInteger(Number(rotationValidity)) || Number(rotationValidity) < 1 || Number(rotationValidity) > 24}
              onClick={() => void exportRotationStatement()}>
              <Download className="h-3.5 w-3.5" /> Export handover statement
            </Button>
            <Input aria-label="Upload dual-signed rotation" type="file" accept=".json,application/json"
              disabled={busy !== null} onChange={(event) => void readRotationFile(event)} />
            <Textarea aria-label="Dual-signed promotion key rotation" className="min-h-28 font-mono text-xs"
              placeholder="Paste the externally dual-signed JSON; never a private key" value={rotationText}
              onChange={(event) => setRotationText(event.target.value)} />
            <Button className="gap-2" disabled={busy !== null || !validRotationSelection || !rotationText.trim()}
              onClick={() => void rotateKey()}>
              <ArrowRightLeft className="h-3.5 w-3.5" /> Accept reviewed key handover
            </Button>
            {keyRotations.filter((rotation) => !rotationSourceId || rotation.source_id === rotationSourceId).slice(0, 5).map((rotation) => (
              <div key={rotation.id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-[#d8dbe0] p-3 text-xs">
                <span>Recorded sequence {rotation.promotion_sequence} · {shortHash(rotation.from_key_fingerprint_sha256)} →{" "}
                  {shortHash(rotation.to_key_fingerprint_sha256)} · {rotation.rotated_by}</span>
                <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => void execute(`rotation-export-${rotation.id}`, async () => {
                  const signed = await apiFetch<Record<string, unknown>>(`/capability-promotions/key-rotations/${rotation.id}/export`);
                  downloadJson(signed, `icheck-promotion-key-rotation-${rotation.id}.json`);
                })}>Export recorded proof</Button>
              </div>
            ))}
          </CardContent>
        </Card>

        <section className="grid gap-4 xl:grid-cols-2">
          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-base">Source: export statement</CardTitle>
              <CardDescription>
                The local pack and transparency head are bound before offline
                signing.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <NativeSelect aria-label="Installed capability pack"
                value={installationId}
                onChange={(event) => setInstallationId(event.target.value)}
              >
                <NativeSelectOption value="">Select installed pack</NativeSelectOption>
                {installedPacks.map((item) => (
                  <NativeSelectOption key={item.id} value={item.id}>
                    {item.pack_name} {item.pack_version}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
              <div className="grid grid-cols-2 gap-2">
                <Input
                  placeholder="Target environment"
                  value={targetEnvironmentId}
                  onChange={(event) => setTargetEnvironmentId(event.target.value)}
                />
                <NativeSelect aria-label="Target promotion stage"
                  value={targetStage}
                  onChange={(event) => setTargetStage(event.target.value as Stage)}
                >
                  {stages.map((stage) => (
                    <NativeSelectOption key={stage} value={stage}>
                      {stage}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <Input
                  type="number"
                  min={1}
                  value={promotionSequence}
                  onChange={(event) => setPromotionSequence(event.target.value)}
                  aria-label="Promotion sequence"
                />
                <Input
                  type="number"
                  min={1}
                  max={168}
                  value={validityHours}
                  onChange={(event) => setValidityHours(event.target.value)}
                  aria-label="Validity hours"
                />
              </div>
              <Input
                className="font-mono text-[10px]"
                placeholder="64-character validation evidence SHA-256"
                value={evidenceDigest}
                onChange={(event) => setEvidenceDigest(event.target.value)}
              />
              <Button
                className="w-full gap-2"
                disabled={
                  busy !== null
                  || !installationId
                  || evidenceDigest.length !== 64
                  || !organizationId.trim()
                }
                onClick={() => void createStatement()}
              >
                <FileSignature className="h-3.5 w-3.5" /> Export statement
              </Button>
              <p className="text-[11px] leading-5 text-muted-foreground">
                This endpoint never signs. Transfer the statement to the
                environment promotion authority and wrap it in the signed v1
                envelope.
              </p>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-base">Target: verify and accept</CardTitle>
              <CardDescription>
                Signature success never bypasses current local pack, dependency,
                revocation, or signer checks.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <label className="flex cursor-pointer items-center justify-center gap-2 rounded-md border border-dashed border-[#aeb6c2] p-4 text-xs">
                <Upload className="h-4 w-4" />
                {attestationFilename || "Choose signed promotion JSON"}
                <input
                  type="file"
                  accept="application/json,.json"
                  className="hidden"
                  onChange={(event) => void readAttestationFile(event)}
                />
              </label>
              <Textarea
                className="min-h-32 font-mono text-[10px]"
                placeholder="Or paste signed promotion attestation JSON"
                value={attestationText}
                onChange={(event) => {
                  setAttestationText(event.target.value);
                  setPreview(null);
                }}
              />
              <Textarea aria-label="Source checkpoint gossip evidence" className="min-h-24 font-mono text-xs"
                placeholder="Optional source checkpoint gossip JSON exported by the witness service"
                value={checkpointEvidenceText} onChange={(event) => setCheckpointEvidenceText(event.target.value)} />
              <Button variant="outline" disabled={busy !== null || !attestationText.trim() || !checkpointEvidenceText.trim()}
                onClick={attachCheckpointEvidence}>Attach source checkpoint evidence</Button>
              <Button
                variant="outline"
                className="w-full gap-2"
                disabled={busy !== null || !attestationText.trim()}
                onClick={() => void previewPromotion()}
              >
                {busy === "preview" ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <ShieldCheck className="h-3.5 w-3.5" />
                )}
                Verify and revalidate
              </Button>
              {preview && (
                <div
                  className={cn(
                    "rounded-lg border p-4",
                    preview.promotable
                      ? "border-emerald-300 bg-emerald-50"
                      : "border-red-300 bg-red-50",
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-semibold">
                      {preview.pack_name} {preview.pack_version}
                    </p>
                    <Badge
                      variant={preview.promotable ? "default" : "destructive"}
                    >
                      {preview.already_accepted
                        ? "already accepted"
                        : preview.promotable
                          ? "promotable"
                          : "blocked"}
                    </Badge>
                  </div>
                  <p className="mt-2 text-[10px] text-[#59677b]">
                    {preview.source_environment_id} →{" "}
                    {preview.target_environment_id} · sequence{" "}
                    {preview.promotion_sequence} · {preview.artifact_count} artifacts
                  </p>
                  <p className="mt-1 text-xs text-[#59677b]">Allowlisted source witnesses {preview.source_witness_count}
                    {" "}· required {preview.required_source_witness_quorum}</p>
                  <p className="mt-1 font-mono text-[9px] text-muted-foreground">
                    source log {preview.source_transparency_log_id} · head{" "}
                    {shortHash(preview.source_transparency_head_sha256)}
                  </p>
                  {preview.blockers.map((blocker) => (
                    <p key={blocker} className="mt-2 text-xs text-red-700">
                      {blocker}
                    </p>
                  ))}
                </div>
              )}
              <Textarea
                rows={3}
                placeholder="Why may this exact pack enter this environment?"
                value={acceptReason}
                onChange={(event) => setAcceptReason(event.target.value)}
              />
              <Button
                className="w-full gap-2"
                disabled={
                  busy !== null
                  || !preview?.promotable
                  || acceptReason.trim().length < 3
                }
                onClick={() => void acceptPromotion()}
              >
                <CheckCircle2 className="h-3.5 w-3.5" /> Accept receipt
              </Button>
              <p className="text-[11px] leading-5 text-muted-foreground">
                Acceptance records qualification only. It does not publish,
                activate, deploy, schedule, or execute any Artifact.
              </p>
            </CardContent>
          </Card>
        </section>

        <Card className="border-[#d8dbe0] shadow-none">
          <CardHeader>
            <CardTitle className="text-base">Promotion receipt ledger</CardTitle>
            <CardDescription>
              Immutable target acceptance with exact signed source evidence.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {receipts.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No promotion receipts accepted.
              </p>
            ) : receipts.map((receipt) => (
              <div
                key={receipt.id}
                className="rounded-lg border border-[#d8dbe0] bg-white p-4"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold">
                      {receipt.pack_name} {receipt.pack_version}
                    </p>
                    <p className="mt-1 text-[10px] text-muted-foreground">
                      {receipt.source_environment_id} ({receipt.source_stage}) →{" "}
                      {receipt.target_environment_id} ({receipt.target_stage}) ·
                      sequence {receipt.promotion_sequence} ·{" "}
                      {new Date(receipt.accepted_at).toLocaleString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {publicationByReceipt.has(receipt.id) && (
                      <Badge>published</Badge>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-2"
                      disabled={busy !== null}
                      onClick={() => void exportReceipt(receipt)}
                    >
                      <Download className="h-3.5 w-3.5" /> Signed envelope
                    </Button>
                    <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => void execute(`witness-export-${receipt.id}`, async () => {
                      const evidence = await apiFetch(`/capability-promotions/receipts/${receipt.id}/source-witness-evidence`);
                      if (evidence === null) {setMessage("This historical receipt has no recorded source witness evidence."); return;}
                      downloadJson(evidence, `icheck-promotion-witness-decision-${receipt.id}.json`);
                    })}>Witness decision</Button>
                  </div>
                </div>
                <div className="mt-3 grid gap-1 font-mono text-[9px] text-muted-foreground md:grid-cols-3">
                  <p>pack {shortHash(receipt.pack_digest_sha256)}</p>
                  <p>statement {shortHash(receipt.statement_digest_sha256)}</p>
                  <p>evidence {shortHash(receipt.validation_evidence_digest_sha256)}</p>
                </div>
                {publicationByReceipt.has(receipt.id) ? (
                  <div className="mt-3 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-[10px] text-emerald-800">
                    Atomic publication recorded · {publicationByReceipt.get(receipt.id)?.newly_published_count} newly published · digest{" "}
                    <span className="font-mono">
                      {shortHash(
                        publicationByReceipt.get(receipt.id)
                          ?.publication_digest_sha256 || null,
                      )}
                    </span>
                  </div>
                ) : (
                  <div className="mt-3 space-y-2 border-t border-[#e3e5e9] pt-3">
                    <Input
                      placeholder="Why may this promoted pack be published now?"
                      value={publicationReasons[receipt.id] || ""}
                      onChange={(event) => (
                        setPublicationReasons((current) => ({
                          ...current,
                          [receipt.id]: event.target.value,
                        }))
                      )}
                    />
                    {publicationPreviews[receipt.id] && (
                      <div
                        className={cn(
                          "rounded-md border px-3 py-2 text-[10px]",
                          publicationPreviews[receipt.id].eligible
                            ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                            : "border-red-200 bg-red-50 text-red-700",
                        )}
                      >
                        <p>
                          {publicationPreviews[receipt.id].candidate_artifact_version_ids.length} to publish ·{" "}
                          {publicationPreviews[receipt.id].already_published_version_ids.length} already published ·{" "}
                          {publicationPreviews[receipt.id].reused_version_ids.length} reused
                        </p>
                        {publicationPreviews[receipt.id].blockers.map((blocker) => (
                          <p key={blocker} className="mt-1 font-mono">
                            {blocker}
                          </p>
                        ))}
                      </div>
                    )}
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={
                          busy !== null
                          || (publicationReasons[receipt.id]?.trim().length || 0) < 3
                        }
                        onClick={() => void previewPublication(receipt)}
                      >
                        Preview publication
                      </Button>
                      <Button
                        size="sm"
                        disabled={
                          busy !== null
                          || !publicationPreviews[receipt.id]?.eligible
                        }
                        onClick={() => void publishReceipt(receipt)}
                      >
                        Publish pack atomically
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
