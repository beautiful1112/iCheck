"use client";

import Link from "next/link";
import { ChangeEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Download,
  Eye,
  FileKey2,
  KeyRound,
  Loader2,
  Power,
  RefreshCw,
  ShieldCheck,
  Upload,
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
  NativeSelect,
  NativeSelectOption,
} from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { apiFetch, getApiNamespace } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type TrustKey = {
  id: string;
  name: string;
  fingerprint_sha256: string;
  enabled: boolean;
  purposes: string[];
  trust_source: "local" | "trust_bundle";
  trust_domain_id: string | null;
  managed_bundle_sequence: number | null;
  expires_at: string | null;
};

type TrustDomain = {
  id: string;
  name: string;
  organization_id: string;
  authority_trust_key_id: string;
  authority_key_fingerprint_sha256: string;
  enabled: boolean;
  allowed_purposes: string[];
  max_bundle_lifetime_days: number;
  max_key_lifetime_days: number;
  latest_sequence: number;
  latest_bundle_digest_sha256: string | null;
  updated_at: string;
};

type BundleReceipt = {
  id: string;
  trust_domain_id: string;
  sequence: number;
  bundle_digest_sha256: string;
  authority_key_fingerprint_sha256: string;
  issued_at: string;
  expires_at: string;
  key_count: number;
  active_key_count: number;
  revoked_key_count: number;
  imported_by: string;
  imported_at: string;
};

type KeyPlan = {
  name: string;
  fingerprint_sha256: string;
  purposes: string[];
  requested_state: "active" | "revoked";
  action: "add" | "update" | "revoke" | "tombstone" | "unchanged";
  blockers: string[];
};

type BundlePreview = {
  trust_domain_id: string;
  organization_id: string;
  sequence: number;
  bundle_digest_sha256: string;
  authority_key_fingerprint_sha256: string;
  issued_at: string;
  expires_at: string;
  key_count: number;
  active_key_count: number;
  revoked_key_count: number;
  installable: boolean;
  blockers: string[];
  keys: KeyPlan[];
};

type RootRotation = {
  id: string;
  trust_domain_id: string;
  from_key_fingerprint_sha256: string;
  to_key_fingerprint_sha256: string;
  bundle_sequence: number;
  statement_digest_sha256: string;
  rotated_by: string;
  rotated_at: string;
};

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

export default function OrganizationTrustPage() {
  const [keys, setKeys] = useState<TrustKey[]>([]);
  const [domains, setDomains] = useState<TrustDomain[]>([]);
  const [receipts, setReceipts] = useState<BundleReceipt[]>([]);
  const [rootRotations, setRootRotations] = useState<RootRotation[]>([]);
  const [selectedDomainId, setSelectedDomainId] = useState("");
  const [rootName, setRootName] = useState("");
  const [rootPem, setRootPem] = useState("");
  const [domainName, setDomainName] = useState("");
  const [organizationId, setOrganizationId] = useState("");
  const [authorityKeyId, setAuthorityKeyId] = useState("");
  const [bundleText, setBundleText] = useState("");
  const [bundleFilename, setBundleFilename] = useState("");
  const [reason, setReason] = useState("");
  const [nextRootKeyId, setNextRootKeyId] = useState("");
  const [rotationText, setRotationText] = useState("");
  const [rotationFilename, setRotationFilename] = useState("");
  const [rotationReason, setRotationReason] = useState("");
  const [preview, setPreview] = useState<BundlePreview | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const pendingDomainCreation = useRef<{ fingerprint: string; key: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const [keyRows, domainRows, receiptRows, rotationRows] = await Promise.all([
        apiFetch<TrustKey[]>("/artifact-trust-keys"),
        apiFetch<TrustDomain[]>("/organization-trust/domains?limit=500"),
        apiFetch<BundleReceipt[]>("/organization-trust/bundles?limit=500"),
        apiFetch<RootRotation[]>(
          "/organization-trust/root-rotations?limit=500",
        ),
      ]);
      setKeys(keyRows);
      setDomains(domainRows);
      setReceipts(receiptRows);
      setRootRotations(rotationRows);
      setSelectedDomainId((current) => current || domainRows[0]?.id || "");
      const roots = keyRows.filter(
        (key) => (
          key.enabled
          && key.trust_source === "local"
          && key.purposes.includes("trust_bundle")
        ),
      );
      setAuthorityKeyId((current) => current || roots[0]?.id || "");
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to load organization trust",
      );
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const rootKeys = useMemo(
    () => keys.filter(
      (key) => (
        key.enabled
        && key.trust_source === "local"
        && key.purposes.includes("trust_bundle")
      ),
    ),
    [keys],
  );
  const selectedDomain =
    domains.find((item) => item.id === selectedDomainId) || null;
  const domainKeys = keys.filter(
    (key) => key.trust_domain_id === selectedDomainId,
  );
  const domainReceipts = receipts.filter(
    (item) => item.trust_domain_id === selectedDomainId,
  );
  const domainRotations = rootRotations.filter(
    (item) => item.trust_domain_id === selectedDomainId,
  );
  const nextRootKeys = rootKeys.filter(
    (key) => key.id !== selectedDomain?.authority_trust_key_id,
  );

  function parsedBundle(): Record<string, unknown> {
    if (!bundleText.trim()) {
      throw new Error("Select or paste a signed trust bundle first");
    }
    const document = JSON.parse(bundleText) as Record<string, unknown>;
    if (!document || Array.isArray(document)) {
      throw new Error("Signed trust bundle must be a JSON object");
    }
    return document;
  }

  async function registerRoot() {
    if (!rootName.trim() || !rootPem.trim()) return;
    setBusy("root");
    setError(null);
    setMessage(null);
    try {
      await apiFetch<TrustKey>("/artifact-trust-keys", {
        method: "POST",
        body: JSON.stringify({
          name: rootName.trim(),
          public_key_pem: rootPem.trim(),
          purposes: ["trust_bundle"],
          created_by: "platform.admin",
        }),
      });
      setRootName("");
      setRootPem("");
      setMessage("Offline organization root public key pinned locally.");
      await load();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Unable to pin root key",
      );
    } finally {
      setBusy(null);
    }
  }

  async function createDomain() {
    if (
      !domainName.trim()
      || !organizationId.trim()
      || !authorityKeyId
    ) return;
    setBusy("domain");
    setError(null);
    setMessage(null);
    try {
      const request = {
        name: domainName.trim(),
        organization_id: organizationId.trim(),
        authority_trust_key_id: authorityKeyId,
        allowed_purposes: [
          "artifact_bundle",
          "capability_pack",
          "capability_revocation",
          "remote_catalog",
          "trust_bundle",
          "transparency_witness",
          "environment_promotion",
        ],
        max_bundle_lifetime_days: 30,
        max_key_lifetime_days: 730,
        created_by: "platform.admin",
      };
      const storageKey = "icheck.trust-domain-creation.v1";
      const fingerprint = JSON.stringify({ namespace: getApiNamespace(), request });
      let previous: { fingerprint?: string; key?: string } | null = pendingDomainCreation.current;
      try {
        const stored = window.sessionStorage.getItem(storageKey);
        if (stored) {
          previous = JSON.parse(stored) as { fingerprint?: string; key?: string } | null;
        }
      } catch {
        // Keep the in-memory attempt when browser storage is unavailable.
      }
      const idempotencyKey = previous?.fingerprint === fingerprint
        && typeof previous.key === "string" && /^[0-9a-f-]{36}$/.test(previous.key)
        ? previous.key : window.crypto.randomUUID();
      pendingDomainCreation.current = { fingerprint, key: idempotencyKey };
      try {
        window.sessionStorage.setItem(storageKey, JSON.stringify(pendingDomainCreation.current));
      } catch {
        // In-memory retry remains available until this page is closed.
      }
      const created = await apiFetch<TrustDomain>(
        "/organization-trust/domains",
        {
          method: "POST",
          body: JSON.stringify({
            ...request,
            idempotency_key: idempotencyKey,
          }),
        },
      );
      pendingDomainCreation.current = null;
      try {
        window.sessionStorage.removeItem(storageKey);
      } catch {
        // Nothing durable was saved if storage is unavailable.
      }
      setSelectedDomainId(created.id);
      setDomainName("");
      setOrganizationId("");
      setMessage("Organization trust domain confirmed; current state loaded.");
      await load();
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to create trust domain",
      );
    } finally {
      setBusy(null);
    }
  }

  async function readBundleFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      setBundleText(await file.text());
      setBundleFilename(file.name);
      setPreview(null);
      setError(null);
    } catch {
      setError("Unable to read the selected trust-bundle file");
    } finally {
      event.target.value = "";
    }
  }

  async function previewBundle() {
    if (!selectedDomainId) return;
    setBusy("preview");
    setError(null);
    setMessage(null);
    try {
      const document = parsedBundle();
      setPreview(
        await apiFetch<BundlePreview>(
          `/organization-trust/domains/${selectedDomainId}/bundles/preview`,
          {
            method: "POST",
            body: JSON.stringify({ signed_bundle: document }),
          },
        ),
      );
    } catch (cause) {
      setPreview(null);
      setError(
        cause instanceof Error
          ? cause.message
          : "Trust-bundle preview failed",
      );
    } finally {
      setBusy(null);
    }
  }

  async function importBundle() {
    if (!selectedDomainId || !preview?.installable || !reason.trim()) return;
    setBusy("import");
    setError(null);
    setMessage(null);
    try {
      const document = parsedBundle();
      await apiFetch<BundleReceipt>(
        `/organization-trust/domains/${selectedDomainId}/bundles/import`,
        {
          method: "POST",
          body: JSON.stringify({
            signed_bundle: document,
            reason: reason.trim(),
            actor: "platform.admin",
          }),
        },
      );
      setMessage(`Trust bundle sequence ${preview.sequence} imported.`);
      setReason("");
      setBundleText("");
      setBundleFilename("");
      setPreview(null);
      await load();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Trust-bundle import failed",
      );
    } finally {
      setBusy(null);
    }
  }

  async function toggleDomain(domain: TrustDomain) {
    setBusy(`state-${domain.id}`);
    setError(null);
    try {
      await apiFetch<TrustDomain>(
        `/organization-trust/domains/${domain.id}/state`,
        {
          method: "POST",
          body: JSON.stringify({
            enabled: !domain.enabled,
            reason: `${domain.enabled ? "Disable" : "Enable"} organization trust after operator review.`,
            actor: "platform.admin",
          }),
        },
      );
      await load();
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to change trust-domain state",
      );
    } finally {
      setBusy(null);
    }
  }

  async function exportReceipt(receipt: BundleReceipt) {
    setBusy(`export-${receipt.id}`);
    try {
      const document = await apiFetch<Record<string, unknown>>(
        `/organization-trust/bundles/${receipt.id}/export`,
      );
      downloadJson(
        document,
        `organization-trust-${receipt.sequence}.json`,
      );
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to export signed trust bundle",
      );
    } finally {
      setBusy(null);
    }
  }

  async function readRotationFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      setRotationText(await file.text());
      setRotationFilename(file.name);
      setError(null);
    } catch {
      setError("Unable to read the selected root-rotation file");
    } finally {
      event.target.value = "";
    }
  }

  async function rotateRoot() {
    if (
      !selectedDomain
      || !nextRootKeyId
      || !rotationText.trim()
      || !rotationReason.trim()
    ) return;
    setBusy("root-rotation");
    setError(null);
    setMessage(null);
    try {
      const signedRotation = JSON.parse(rotationText) as Record<
        string,
        unknown
      >;
      await apiFetch<RootRotation>(
        `/organization-trust/domains/${selectedDomain.id}/rotate-root`,
        {
          method: "POST",
          body: JSON.stringify({
            new_authority_trust_key_id: nextRootKeyId,
            signed_rotation: signedRotation,
            reason: rotationReason.trim(),
            actor: "platform.admin",
          }),
        },
      );
      setNextRootKeyId("");
      setRotationText("");
      setRotationFilename("");
      setRotationReason("");
      setMessage("Dual-signed organization root rotation accepted.");
      await load();
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Organization root rotation failed",
      );
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="min-h-screen bg-[#eef0f5] text-[#253044]">
      <header className="border-b border-[#d8dbe0] bg-white">
        <div className="mx-auto flex min-h-16 max-w-[1500px] items-center gap-3 px-5">
          <Link
            href="/studio/catalog"
            className="rounded-md p-2 text-[#59677b] hover:bg-[#eef0f5]"
            aria-label="Back to catalog"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-[#171c2a] text-white">
            <ShieldCheck className="h-4 w-4" />
          </span>
          <div>
            <h1 className="text-sm font-semibold">
              Organization trust distribution
            </h1>
            <p className="text-xs text-muted-foreground">
              Offline root pin → signed complete snapshot → purpose-scoped trust
            </p>
            <p className="mt-1 text-[11px] text-muted-foreground">
              Pins and revocations apply only to the selected tenant and region.
              Accept the same publisher separately in each namespace.
            </p>
          </div>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/transparency" className="ml-auto">Transparency</Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/trust/recovery">Emergency recovery</Link>
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            onClick={() => void load()}
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
        </div>
      </header>

      <div className="mx-auto max-w-[1500px] space-y-5 px-5 py-6">
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

        <section className="grid gap-4 xl:grid-cols-2">
          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <KeyRound className="h-4 w-4" /> 1. Pin an offline root
              </CardTitle>
              <CardDescription>
                Only the public Ed25519 key is accepted. iCheck never receives
                a private signing key.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Input
                value={rootName}
                onChange={(event) => setRootName(event.target.value)}
                placeholder="offline-org-root-2026"
              />
              <Textarea
                value={rootPem}
                onChange={(event) => setRootPem(event.target.value)}
                placeholder="-----BEGIN PUBLIC KEY-----"
                className="min-h-28 font-mono text-[10px]"
              />
              <Button
                size="sm"
                disabled={
                  busy === "root" || !rootName.trim() || !rootPem.trim()
                }
                onClick={() => void registerRoot()}
              >
                {busy === "root" && (
                  <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
                )}
                Pin public root
              </Button>
            </CardContent>
          </Card>

          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <FileKey2 className="h-4 w-4" /> 2. Create a local trust domain
              </CardTitle>
              <CardDescription>
                Identity and root are immutable. A signed bundle cannot enlarge
                local lifetime or purpose policy.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid gap-3 md:grid-cols-2">
                <Input
                  value={domainName}
                  onChange={(event) => setDomainName(event.target.value)}
                  placeholder="Example operations"
                />
                <Input
                  value={organizationId}
                  onChange={(event) => setOrganizationId(event.target.value)}
                  placeholder="example-operations"
                />
              </div>
              <NativeSelect aria-label="Organization authority key"
                value={authorityKeyId}
                onChange={(event) => setAuthorityKeyId(event.target.value)}
              >
                <NativeSelectOption value="">
                  Select pinned trust-bundle root
                </NativeSelectOption>
                {rootKeys.map((key) => (
                  <NativeSelectOption key={key.id} value={key.id}>
                    {key.name} · {shortHash(key.fingerprint_sha256)}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
              <Button
                size="sm"
                disabled={
                  busy === "domain"
                  || !domainName.trim()
                  || !organizationId.trim()
                  || !authorityKeyId
                }
                onClick={() => void createDomain()}
              >
                {busy === "domain" && (
                  <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
                )}
                Create trust domain
              </Button>
              <p className="text-xs text-muted-foreground">
                If the response is lost, retry the unchanged request to recover its result.
              </p>
            </CardContent>
          </Card>
        </section>

        <Card className="border-[#d8dbe0] shadow-none">
          <CardHeader>
            <CardTitle className="text-sm">Trust domains</CardTitle>
            <CardDescription>
              Disabling a domain immediately makes every distributed key
              unusable without deleting evidence.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
            {domains.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                No trust domains configured.
              </p>
            ) : domains.map((domain) => (
              <button
                key={domain.id}
                type="button"
                onClick={() => {
                  setSelectedDomainId(domain.id);
                  setPreview(null);
                }}
                className={cn(
                  "rounded-lg border bg-white p-4 text-left",
                  selectedDomainId === domain.id
                    ? "border-violet-400 ring-2 ring-violet-100"
                    : "border-[#d8dbe0]",
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold">{domain.name}</p>
                    <p className="mt-1 text-[10px] text-muted-foreground">
                      {domain.organization_id}
                    </p>
                  </div>
                  <Badge
                    variant="outline"
                    className={
                      domain.enabled
                        ? "border-emerald-300 bg-emerald-50 text-emerald-700"
                        : "border-red-300 bg-red-50 text-red-700"
                    }
                  >
                    {domain.enabled ? "enabled" : "disabled"}
                  </Badge>
                </div>
                <p className="mt-3 font-mono text-[9px] text-muted-foreground">
                  root {shortHash(domain.authority_key_fingerprint_sha256)}
                </p>
                <p className="mt-1 font-mono text-[9px] text-muted-foreground">
                  sequence {domain.latest_sequence} · head{" "}
                  {shortHash(domain.latest_bundle_digest_sha256)}
                </p>
              </button>
            ))}
          </CardContent>
        </Card>

        {selectedDomain && (
          <section className="grid gap-5 xl:grid-cols-[minmax(0,1.1fr)_minmax(420px,.9fr)]">
            <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <CardTitle className="text-sm">
                      3. Preview and import a signed snapshot
                    </CardTitle>
                    <CardDescription>
                      Sequence must be exactly {selectedDomain.latest_sequence + 1}.
                      The snapshot is complete: omitted managed keys are revoked.
                    </CardDescription>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-2"
                    disabled={busy === `state-${selectedDomain.id}`}
                    onClick={() => void toggleDomain(selectedDomain)}
                  >
                    <Power className="h-3.5 w-3.5" />
                    {selectedDomain.enabled ? "Disable" : "Enable"}
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <label className="flex cursor-pointer items-center justify-center gap-2 rounded-lg border border-dashed border-[#cbd1da] bg-[#f8f9fb] px-4 py-5 text-xs text-[#59677b] hover:border-violet-300">
                  <Upload className="h-4 w-4" />
                  {bundleFilename || "Choose signed organization trust JSON"}
                  <input
                    type="file"
                    accept="application/json,.json"
                    className="sr-only"
                    onChange={(event) => void readBundleFile(event)}
                  />
                </label>
                <Textarea
                  value={bundleText}
                  onChange={(event) => {
                    setBundleText(event.target.value);
                    setPreview(null);
                  }}
                  placeholder="Or paste the signed trust bundle JSON"
                  className="min-h-36 font-mono text-[10px]"
                />
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-2"
                  disabled={!bundleText.trim() || busy === "preview"}
                  onClick={() => void previewBundle()}
                >
                  {busy === "preview" ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Eye className="h-3.5 w-3.5" />
                  )}
                  Preview
                </Button>

                {preview && (
                  <div
                    className={cn(
                      "rounded-lg border p-4",
                      preview.installable
                        ? "border-emerald-200 bg-emerald-50/50"
                        : "border-red-200 bg-red-50/50",
                    )}
                  >
                    <div className="flex items-center gap-2">
                      {preview.installable ? (
                        <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-600" />
                      )}
                      <p className="text-sm font-semibold">
                        Sequence {preview.sequence}{" "}
                        {preview.installable ? "is installable" : "is blocked"}
                      </p>
                    </div>
                    <p className="mt-2 break-all font-mono text-[9px] text-muted-foreground">
                      digest {preview.bundle_digest_sha256}
                    </p>
                    {preview.blockers.length > 0 && (
                      <p className="mt-2 text-[10px] text-red-700">
                        {preview.blockers.join(" · ")}
                      </p>
                    )}
                    <div className="mt-3 space-y-2">
                      {preview.keys.map((plan) => (
                        <div
                          key={plan.fingerprint_sha256}
                          className="rounded-md border border-white bg-white/80 p-2 text-[10px]"
                        >
                          <div className="flex justify-between gap-3">
                            <span className="font-semibold">{plan.name}</span>
                            <Badge variant="outline" className="text-[9px]">
                              {plan.action}
                            </Badge>
                          </div>
                          <p className="mt-1 text-muted-foreground">
                            {plan.requested_state} · {plan.purposes.join(", ")}
                            {" "}· {shortHash(plan.fingerprint_sha256)}
                          </p>
                          {plan.blockers.length > 0 && (
                            <p className="mt-1 text-red-700">
                              {plan.blockers.join(" · ")}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                    <Input
                      className="mt-3 bg-white"
                      value={reason}
                      onChange={(event) => setReason(event.target.value)}
                      placeholder="Required change reason"
                    />
                    <Button
                      size="sm"
                      className="mt-3"
                      disabled={
                        !preview.installable
                        || !reason.trim()
                        || busy === "import"
                      }
                      onClick={() => void importBundle()}
                    >
                      {busy === "import" && (
                        <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
                      )}
                      Import signed snapshot
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            <div className="space-y-5">
              <Card className="border-[#d8dbe0] shadow-none">
                <CardHeader>
                  <CardTitle className="text-sm">
                    Dual-control root rotation
                  </CardTitle>
                  <CardDescription>
                    Pin the next public root first, then upload a statement
                    signed by both the current and next roots. It must bind
                    sequence {selectedDomain.latest_sequence} and the current
                    bundle head.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <NativeSelect aria-label="Next pinned root key"
                    value={nextRootKeyId}
                    onChange={(event) => setNextRootKeyId(event.target.value)}
                  >
                    <NativeSelectOption value="">
                      Select next pinned local root
                    </NativeSelectOption>
                    {nextRootKeys.map((key) => (
                      <NativeSelectOption key={key.id} value={key.id}>
                        {key.name} · {shortHash(key.fingerprint_sha256)}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                  <label className="flex cursor-pointer items-center justify-center gap-2 rounded-lg border border-dashed border-[#cbd1da] bg-[#f8f9fb] px-3 py-3 text-[10px] text-[#59677b] hover:border-violet-300">
                    <Upload className="h-3.5 w-3.5" />
                    {rotationFilename || "Choose dual-signed rotation JSON"}
                    <input
                      type="file"
                      accept="application/json,.json"
                      className="sr-only"
                      onChange={(event) => void readRotationFile(event)}
                    />
                  </label>
                  <Textarea
                    value={rotationText}
                    onChange={(event) => setRotationText(event.target.value)}
                    placeholder="Or paste the signed root-rotation envelope"
                    className="min-h-24 font-mono text-[9px]"
                  />
                  <Input
                    value={rotationReason}
                    onChange={(event) => setRotationReason(event.target.value)}
                    placeholder="Required rotation reason"
                  />
                  <Button
                    size="sm"
                    disabled={
                      !nextRootKeyId
                      || !rotationText.trim()
                      || !rotationReason.trim()
                      || busy === "root-rotation"
                    }
                    onClick={() => void rotateRoot()}
                  >
                    {busy === "root-rotation" && (
                      <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
                    )}
                    Rotate organization root
                  </Button>
                  {domainRotations.map((rotation) => (
                    <div
                      key={rotation.id}
                      className="rounded-md border border-[#d8dbe0] bg-white p-2 text-[9px] text-muted-foreground"
                    >
                      <p>
                        {shortHash(rotation.from_key_fingerprint_sha256)} →{" "}
                        {shortHash(rotation.to_key_fingerprint_sha256)}
                      </p>
                      <p className="mt-1">
                        sequence {rotation.bundle_sequence} ·{" "}
                        {new Date(rotation.rotated_at).toLocaleString()}
                      </p>
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Card className="border-[#d8dbe0] shadow-none">
                <CardHeader>
                  <CardTitle className="text-sm">Purpose-scoped keys</CardTitle>
                  <CardDescription>
                    Current keys managed by {selectedDomain.organization_id}.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {domainKeys.length === 0 ? (
                    <p className="text-xs text-muted-foreground">
                      No distributed keys imported.
                    </p>
                  ) : domainKeys.map((key) => (
                    <div
                      key={key.id}
                      className="rounded-lg border border-[#d8dbe0] bg-white p-3"
                    >
                      <div className="flex justify-between gap-3">
                        <p className="text-xs font-semibold">{key.name}</p>
                        <Badge
                          variant="outline"
                          className={
                            key.enabled ? "text-emerald-700" : "text-red-700"
                          }
                        >
                          {key.enabled ? "active" : "revoked"}
                        </Badge>
                      </div>
                      <p className="mt-1 text-[10px] text-muted-foreground">
                        {key.purposes.join(", ")} · sequence{" "}
                        {key.managed_bundle_sequence}
                      </p>
                      <p className="mt-1 font-mono text-[9px] text-muted-foreground">
                        {shortHash(key.fingerprint_sha256)}
                      </p>
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Card className="border-[#d8dbe0] shadow-none">
                <CardHeader>
                  <CardTitle className="text-sm">Immutable receipts</CardTitle>
                  <CardDescription>
                    Export the exact accepted signed envelope for recovery or
                    peer promotion.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {domainReceipts.length === 0 ? (
                    <p className="text-xs text-muted-foreground">
                      No accepted snapshots.
                    </p>
                  ) : domainReceipts.map((receipt) => (
                    <div
                      key={receipt.id}
                      className="flex items-center justify-between gap-3 rounded-lg border border-[#d8dbe0] bg-white p-3"
                    >
                      <div>
                        <p className="text-xs font-semibold">
                          Sequence {receipt.sequence}
                        </p>
                        <p className="mt-1 text-[9px] text-muted-foreground">
                          {receipt.active_key_count} active ·{" "}
                          {receipt.revoked_key_count} revoked ·{" "}
                          {new Date(receipt.imported_at).toLocaleString()}
                        </p>
                        <p className="mt-1 font-mono text-[9px] text-muted-foreground">
                          {shortHash(receipt.bundle_digest_sha256)}
                        </p>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        className="gap-2"
                        disabled={busy === `export-${receipt.id}`}
                        onClick={() => void exportReceipt(receipt)}
                      >
                        <Download className="h-3.5 w-3.5" /> Export
                      </Button>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
