"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Download,
  Eye,
  KeyRound,
  Loader2,
  RefreshCw,
  ShieldAlert,
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
import { apiFetch } from "@/lib/icheck-api";

type TrustKey = {
  id: string;
  name: string;
  fingerprint_sha256: string;
  enabled: boolean;
  purposes: string[];
  trust_source: string;
};

type TrustDomain = {
  id: string;
  name: string;
  organization_id: string;
  authority_trust_key_id: string;
  authority_key_fingerprint_sha256: string;
  enabled: boolean;
  latest_sequence: number;
  latest_bundle_digest_sha256: string | null;
};

type RecoveryPolicy = {
  id: string;
  trust_domain_id: string;
  version: number;
  active: boolean;
  trustee_key_ids: string[];
  trustee_key_fingerprints_sha256: string[];
  required_approvals: number;
  delay_hours: number;
  statement_digest_sha256: string;
  transparency_sequence: number;
  created_at: string;
};

type ReanchorPreview = {
  trust_domain_id: string;
  recovery_policy_id: string;
  recovery_policy_version: number;
  ceremony_id: string;
  from_key_fingerprint_sha256: string;
  to_key_fingerprint_sha256: string;
  witness_checkpoint_offer_id: string;
  witness_sequence: number;
  trustee_approval_count: number;
  required_approvals: number;
  execute_delay_hours: number;
  eligible: boolean;
  blockers: string[];
};

type Reanchor = {
  id: string;
  trust_domain_id: string;
  ceremony_id: string;
  from_key_fingerprint_sha256: string;
  to_key_fingerprint_sha256: string;
  trustee_approval_count: number;
  status: "pending" | "executed" | "cancelled";
  execute_after: string;
  proposal_transparency_sequence: number | null;
  execution_transparency_sequence: number | null;
  proposed_by: string;
  proposed_at: string;
  executed_by: string | null;
};

type CredentialProfile = {
  id: string;
  name: string;
  allowed_adapters: string[];
  worker_selector: Record<string, string>;
  enabled: boolean;
};

type SigningProvider = {
  id: string;
  name: string;
  provider_kind: "hsm_gateway" | "kms_gateway";
  url: string;
  signing_key_ref: string;
  trust_key_id: string;
  key_fingerprint_sha256: string;
  credential_profile_ref: string | null;
  tls_mode: "server_auth" | "mutual_tls";
  tls_ca_certificate_ref: string | null;
  tls_client_certificate_ref: string | null;
  tls_client_private_key_ref: string | null;
  tls_client_private_key_password_ref: string | null;
  tls_revision: number;
  enabled: boolean;
  last_success_at: string | null;
};

type SigningEvent = {
  id: string;
  provider_id: string;
  document_type: "recovery_policy" | "root_reanchor";
  statement_digest_sha256: string;
  request_digest_sha256: string;
  key_fingerprint_sha256: string;
  signature_sha256: string;
  tls_evidence: {
    mode?: string;
    tls_revision?: number;
    hostname_verification?: boolean;
  };
  requested_by: string;
  requested_at: string;
};

function shortHash(value: string | null) {
  return value ? `${value.slice(0, 12)}…` : "—";
}

function parseDocument(value: string, label: string) {
  if (!value.trim()) throw new Error(`Paste the ${label} JSON first`);
  const document = JSON.parse(value) as Record<string, unknown>;
  if (!document || Array.isArray(document)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return document;
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

export default function TrustRecoveryPage() {
  const [keys, setKeys] = useState<TrustKey[]>([]);
  const [domains, setDomains] = useState<TrustDomain[]>([]);
  const [policies, setPolicies] = useState<RecoveryPolicy[]>([]);
  const [reanchors, setReanchors] = useState<Reanchor[]>([]);
  const [credentials, setCredentials] = useState<CredentialProfile[]>([]);
  const [signingProviders, setSigningProviders] = useState<SigningProvider[]>([]);
  const [signingEvents, setSigningEvents] = useState<SigningEvent[]>([]);
  const [domainId, setDomainId] = useState("");
  const [providerName, setProviderName] = useState("");
  const [providerKind, setProviderKind] = useState<"hsm_gateway" | "kms_gateway">("hsm_gateway");
  const [providerUrl, setProviderUrl] = useState("");
  const [signingKeyRef, setSigningKeyRef] = useState("");
  const [providerTrustKeyId, setProviderTrustKeyId] = useState("");
  const [providerCredentialRef, setProviderCredentialRef] = useState("");
  const [providerTlsMode, setProviderTlsMode] = useState<"server_auth" | "mutual_tls">("server_auth");
  const [providerCaRef, setProviderCaRef] = useState("");
  const [providerCertificateRef, setProviderCertificateRef] = useState("");
  const [providerPrivateKeyRef, setProviderPrivateKeyRef] = useState("");
  const [providerPasswordRef, setProviderPasswordRef] = useState("");
  const [tlsProviderId, setTlsProviderId] = useState("");
  const [tlsMode, setTlsMode] = useState<"server_auth" | "mutual_tls">("server_auth");
  const [tlsCaRef, setTlsCaRef] = useState("");
  const [tlsCertificateRef, setTlsCertificateRef] = useState("");
  const [tlsPrivateKeyRef, setTlsPrivateKeyRef] = useState("");
  const [tlsPasswordRef, setTlsPasswordRef] = useState("");
  const [trusteeName, setTrusteeName] = useState("");
  const [trusteePem, setTrusteePem] = useState("");
  const [trusteeIds, setTrusteeIds] = useState<string[]>([]);
  const [requiredApprovals, setRequiredApprovals] = useState("2");
  const [delayHours, setDelayHours] = useState("24");
  const [policyStatement, setPolicyStatement] = useState<Record<
    string,
    unknown
  > | null>(null);
  const [policyProviderId, setPolicyProviderId] = useState("");
  const [signedPolicyText, setSignedPolicyText] = useState("");
  const [policyReason, setPolicyReason] = useState("");
  const [nextRootId, setNextRootId] = useState("");
  const [reanchorStatement, setReanchorStatement] = useState<Record<
    string,
    unknown
  > | null>(null);
  const [reanchorNextProviderId, setReanchorNextProviderId] = useState("");
  const [reanchorTrusteeProviderIds, setReanchorTrusteeProviderIds] = useState<string[]>([]);
  const [signedReanchorText, setSignedReanchorText] = useState("");
  const [reanchorReason, setReanchorReason] = useState("");
  const [preview, setPreview] = useState<ReanchorPreview | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [
        keyRows,
        domainRows,
        policyRows,
        reanchorRows,
        credentialRows,
        providerRows,
        eventRows,
      ] = await Promise.all([
        apiFetch<TrustKey[]>("/artifact-trust-keys"),
        apiFetch<TrustDomain[]>("/organization-trust/domains?limit=500"),
        apiFetch<RecoveryPolicy[]>(
          "/organization-trust/recovery-policies?limit=500",
        ),
        apiFetch<Reanchor[]>("/organization-trust/root-reanchors?limit=500"),
        apiFetch<CredentialProfile[]>("/credential-profiles?enabled=true&limit=500"),
        apiFetch<SigningProvider[]>(
          "/organization-trust/recovery-signing/providers?limit=500",
        ),
        apiFetch<SigningEvent[]>(
          "/organization-trust/recovery-signing/events?limit=100",
        ),
      ]);
      setKeys(keyRows);
      setDomains(domainRows);
      setPolicies(policyRows);
      setReanchors(reanchorRows);
      setCredentials(credentialRows);
      setSigningProviders(providerRows);
      setSigningEvents(eventRows);
      setDomainId((current) => current || domainRows[0]?.id || "");
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load recovery state");
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const selectedDomain = domains.find((item) => item.id === domainId) || null;
  const recoveryKeys = useMemo(
    () => keys.filter((key) => (
      key.enabled
      && key.trust_source === "local"
      && key.purposes.includes("trust_recovery")
    )),
    [keys],
  );
  const rootKeys = useMemo(
    () => keys.filter((key) => (
      key.enabled
      && key.trust_source === "local"
      && key.purposes.includes("trust_bundle")
      && key.id !== selectedDomain?.authority_trust_key_id
    )),
    [keys, selectedDomain?.authority_trust_key_id],
  );
  const signerCredentials = useMemo(
    () => credentials.filter((credential) => (
      credential.enabled
      && Object.keys(credential.worker_selector).length === 0
      && credential.allowed_adapters.includes("trust_recovery_signing")
    )),
    [credentials],
  );
  const currentRootProviders = signingProviders.filter((provider) => (
    provider.enabled
    && provider.trust_key_id === selectedDomain?.authority_trust_key_id
  ));
  const nextRootProviders = signingProviders.filter((provider) => (
    provider.enabled && provider.trust_key_id === nextRootId
  ));
  const domainPolicies = policies.filter((item) => item.trust_domain_id === domainId);
  const activePolicy = domainPolicies.find((item) => item.active) || null;
  const authorizedTrusteeKeyIds = activePolicy?.trustee_key_ids || trusteeIds;
  const trusteeProviders = signingProviders.filter((provider) => (
    provider.enabled && authorizedTrusteeKeyIds.includes(provider.trust_key_id)
  ));
  const domainReanchors = reanchors.filter((item) => item.trust_domain_id === domainId);

  async function registerSigningProvider() {
    if (
      !providerName.trim()
      || !providerUrl.trim()
      || !signingKeyRef.trim()
      || !providerTrustKeyId
    ) return;
    setBusy("provider-create");
    setError(null);
    try {
      await apiFetch<SigningProvider>(
        "/organization-trust/recovery-signing/providers",
        {
          method: "POST",
          body: JSON.stringify({
            name: providerName.trim(),
            provider_kind: providerKind,
            url: providerUrl.trim(),
            signing_key_ref: signingKeyRef.trim(),
            trust_key_id: providerTrustKeyId,
            credential_profile_ref: providerCredentialRef || null,
            tls_mode: providerTlsMode,
            tls_ca_certificate_ref: providerCaRef.trim() || null,
            tls_client_certificate_ref: providerTlsMode === "mutual_tls"
              ? providerCertificateRef.trim() || null
              : null,
            tls_client_private_key_ref: providerTlsMode === "mutual_tls"
              ? providerPrivateKeyRef.trim() || null
              : null,
            tls_client_private_key_password_ref: providerTlsMode === "mutual_tls"
              ? providerPasswordRef.trim() || null
              : null,
            created_by: "security.architect",
          }),
        },
      );
      setProviderName("");
      setProviderUrl("");
      setSigningKeyRef("");
      setProviderTrustKeyId("");
      setProviderCredentialRef("");
      setProviderCaRef("");
      setProviderCertificateRef("");
      setProviderPrivateKeyRef("");
      setProviderPasswordRef("");
      setMessage("External signer pinned to the selected local public key.");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to register signing provider");
    } finally {
      setBusy(null);
    }
  }

  async function setSigningProviderState(provider: SigningProvider) {
    setBusy(`provider-state-${provider.id}`);
    setError(null);
    try {
      await apiFetch<SigningProvider>(
        `/organization-trust/recovery-signing/providers/${provider.id}/state`,
        {
          method: "POST",
          body: JSON.stringify({
            enabled: !provider.enabled,
            reason: provider.enabled
              ? "Break-glass disable of the external recovery signer."
              : "Re-enable the reviewed external recovery signer.",
            actor: "security.architect",
          }),
        },
      );
      setMessage(provider.enabled ? "Signing provider disabled." : "Signing provider enabled.");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to change signing provider state");
    } finally {
      setBusy(null);
    }
  }

  async function rotateSigningTLS() {
    const provider = signingProviders.find((item) => item.id === tlsProviderId);
    if (!provider) return;
    setBusy("provider-tls");
    setError(null);
    try {
      await apiFetch<SigningProvider>(
        `/organization-trust/recovery-signing/providers/${provider.id}/tls`,
        {
          method: "PUT",
          body: JSON.stringify({
            expected_tls_revision: provider.tls_revision,
            tls_mode: tlsMode,
            tls_ca_certificate_ref: tlsCaRef.trim() || null,
            tls_client_certificate_ref: tlsMode === "mutual_tls"
              ? tlsCertificateRef.trim() || null
              : null,
            tls_client_private_key_ref: tlsMode === "mutual_tls"
              ? tlsPrivateKeyRef.trim() || null
              : null,
            tls_client_private_key_password_ref: tlsMode === "mutual_tls"
              ? tlsPasswordRef.trim() || null
              : null,
            reason: "Rotate the external recovery signing TLS trust material.",
            actor: "security.architect",
          }),
        },
      );
      setMessage(`TLS binding rotated to revision ${provider.tls_revision + 1}.`);
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to rotate signing TLS");
    } finally {
      setBusy(null);
    }
  }

  async function signPolicyWithProvider() {
    if (!selectedDomain || !policyStatement || !policyProviderId) return;
    setBusy("policy-sign");
    setError(null);
    try {
      const signed = await apiFetch<Record<string, unknown>>(
        `/organization-trust/domains/${selectedDomain.id}/recovery-policy-statements/sign`,
        {
          method: "POST",
          body: JSON.stringify({
            provider_id: policyProviderId,
            statement: policyStatement,
            actor: "security.architect",
          }),
        },
      );
      setSignedPolicyText(JSON.stringify(signed, null, 2));
      setMessage("The current-root signature was returned and verified against the pinned public key.");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to sign recovery policy");
    } finally {
      setBusy(null);
    }
  }

  async function signReanchorWithProviders() {
    if (
      !selectedDomain
      || !reanchorStatement
      || !reanchorNextProviderId
      || reanchorTrusteeProviderIds.length < (activePolicy?.required_approvals || 2)
    ) return;
    setBusy("reanchor-sign");
    setError(null);
    try {
      const signed = await apiFetch<Record<string, unknown>>(
        `/organization-trust/domains/${selectedDomain.id}/root-reanchor-statements/sign`,
        {
          method: "POST",
          body: JSON.stringify({
            next_root_provider_id: reanchorNextProviderId,
            trustee_provider_ids: reanchorTrusteeProviderIds,
            statement: reanchorStatement,
            actor: "recovery.proposer",
          }),
        },
      );
      setSignedReanchorText(JSON.stringify(signed, null, 2));
      setPreview(null);
      setMessage("Next-root and trustee signatures were assembled and independently verified.");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to assemble recovery signatures");
    } finally {
      setBusy(null);
    }
  }

  async function registerTrustee() {
    if (!trusteeName.trim() || !trusteePem.trim()) return;
    setBusy("trustee");
    setError(null);
    try {
      await apiFetch<TrustKey>("/artifact-trust-keys", {
        method: "POST",
        body: JSON.stringify({
          name: trusteeName.trim(),
          public_key_pem: trusteePem.trim(),
          purposes: ["trust_recovery"],
          created_by: "platform.admin",
        }),
      });
      setTrusteeName("");
      setTrusteePem("");
      setMessage("Recovery trustee public key pinned locally.");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to register trustee");
    } finally {
      setBusy(null);
    }
  }

  async function generatePolicyStatement() {
    if (!selectedDomain || trusteeIds.length < 2) return;
    setBusy("policy-statement");
    setError(null);
    try {
      const statement = await apiFetch<Record<string, unknown>>(
        `/organization-trust/domains/${selectedDomain.id}/recovery-policy-statements`,
        {
          method: "POST",
          body: JSON.stringify({
            trustee_trust_key_ids: trusteeIds,
            required_approvals: Number(requiredApprovals),
            delay_hours: Number(delayHours),
            validity_hours: 24,
            actor: "security.architect",
          }),
        },
      );
      setPolicyStatement(statement);
      downloadJson(statement, `recovery-policy-${selectedDomain.organization_id}.json`);
      setMessage("Unsigned policy statement generated. Sign it with the current offline root.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to generate policy statement");
    } finally {
      setBusy(null);
    }
  }

  async function authorizePolicy() {
    if (!selectedDomain || !signedPolicyText.trim() || !policyReason.trim()) return;
    setBusy("policy-authorize");
    setError(null);
    try {
      await apiFetch<RecoveryPolicy>(
        `/organization-trust/domains/${selectedDomain.id}/recovery-policies`,
        {
          method: "POST",
          body: JSON.stringify({
            trustee_trust_key_ids: trusteeIds,
            signed_policy: parseDocument(signedPolicyText, "signed recovery policy"),
            reason: policyReason.trim(),
            actor: "security.architect",
          }),
        },
      );
      setSignedPolicyText("");
      setPolicyReason("");
      setPolicyStatement(null);
      setMessage("Root-signed recovery policy authorized and added to transparency.");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to authorize recovery policy");
    } finally {
      setBusy(null);
    }
  }

  async function containDomain() {
    if (!selectedDomain || !selectedDomain.enabled) return;
    setBusy("contain");
    setError(null);
    try {
      await apiFetch<TrustDomain>(
        `/organization-trust/domains/${selectedDomain.id}/state`,
        {
          method: "POST",
          body: JSON.stringify({
            enabled: false,
            reason: "Contain the trust domain before emergency root recovery.",
            actor: "incident.commander",
          }),
        },
      );
      setMessage("Trust domain disabled. Obtain witness quorum before generating a ceremony.");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to contain trust domain");
    } finally {
      setBusy(null);
    }
  }

  async function generateReanchorStatement() {
    if (!selectedDomain || !nextRootId) return;
    setBusy("reanchor-statement");
    setError(null);
    try {
      const statement = await apiFetch<Record<string, unknown>>(
        `/organization-trust/domains/${selectedDomain.id}/root-reanchor-statements`,
        {
          method: "POST",
          body: JSON.stringify({
            new_authority_trust_key_id: nextRootId,
            validity_hours: 168,
            reason: "Generate a witnessed emergency root re-anchor ceremony.",
            actor: "recovery.proposer",
          }),
        },
      );
      setReanchorStatement(statement);
      downloadJson(statement, `root-reanchor-${selectedDomain.organization_id}.json`);
      setMessage("Unsigned ceremony generated. The next root and trustee quorum must sign it.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to generate re-anchor statement");
    } finally {
      setBusy(null);
    }
  }

  async function previewReanchor() {
    if (!selectedDomain || !nextRootId || !signedReanchorText.trim()) return;
    setBusy("preview");
    setError(null);
    try {
      setPreview(await apiFetch<ReanchorPreview>(
        `/organization-trust/domains/${selectedDomain.id}/root-reanchors/preview`,
        {
          method: "POST",
          body: JSON.stringify({
            new_authority_trust_key_id: nextRootId,
            signed_reanchor: parseDocument(signedReanchorText, "signed re-anchor"),
          }),
        },
      ));
    } catch (cause) {
      setPreview(null);
      setError(cause instanceof Error ? cause.message : "Re-anchor preview failed");
    } finally {
      setBusy(null);
    }
  }

  async function proposeReanchor() {
    if (!selectedDomain || !preview?.eligible || !reanchorReason.trim()) return;
    setBusy("propose");
    setError(null);
    try {
      await apiFetch<Reanchor>(
        `/organization-trust/domains/${selectedDomain.id}/root-reanchors`,
        {
          method: "POST",
          body: JSON.stringify({
            new_authority_trust_key_id: nextRootId,
            signed_reanchor: parseDocument(signedReanchorText, "signed re-anchor"),
            reason: reanchorReason.trim(),
            actor: "recovery.proposer",
          }),
        },
      );
      setPreview(null);
      setSignedReanchorText("");
      setReanchorStatement(null);
      setReanchorReason("");
      setMessage("Recovery proposed. Wait, witness the proposal checkpoint, then use a second administrator.");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to propose re-anchor");
    } finally {
      setBusy(null);
    }
  }

  async function actOnRequest(request: Reanchor, action: "execute" | "cancel") {
    setBusy(`${action}-${request.id}`);
    setError(null);
    try {
      await apiFetch<Reanchor>(
        `/organization-trust/root-reanchors/${request.id}/${action}`,
        {
          method: "POST",
          body: JSON.stringify({
            reason: action === "execute"
              ? "Second administrator executes the witnessed recovery."
              : "Cancel the emergency recovery ceremony.",
            actor: action === "execute" ? "recovery.executor" : "incident.commander",
          }),
        },
      );
      setMessage(action === "execute"
        ? "Root re-anchored. Keep the domain disabled until the execution is witnessed."
        : "Recovery ceremony cancelled and recorded in transparency.");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : `Unable to ${action} recovery`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="min-h-screen bg-[#eef0f5] text-[#253044]">
      <header className="border-b border-[#d8dbe0] bg-white">
        <div className="mx-auto flex min-h-16 max-w-[1500px] items-center gap-3 px-5">
          <Link href="/studio/catalog/trust" aria-label="Back to organization trust" className="rounded-md p-2 text-[#59677b] hover:bg-[#eef0f5]">
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-red-950 text-white">
            <ShieldAlert className="h-4 w-4" />
          </span>
          <div>
            <h1 className="text-sm font-semibold">Emergency trust-root recovery</h1>
            <p className="text-xs text-muted-foreground">Pre-authorized trustees · three witness gates · delayed four-eyes execution</p>
          </div>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/transparency/witnesses" className="ml-auto">Witnesses</Link>
          </Button>
          <Button variant="outline" size="sm" className="gap-2" onClick={() => void load()}>
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
        </div>
      </header>

      <div className="mx-auto max-w-[1500px] space-y-5 px-5 py-6">
        <div className="rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-xs text-amber-900">
          This path is only for an unavailable or compromised current root. A normal change must use dual-signed root rotation.
        </div>
        {error && <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-xs text-red-700">{error}</div>}
        {message && <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-xs text-emerald-700">{message}</div>}

        <Card className="border-[#d8dbe0] shadow-none">
          <CardHeader>
            <CardTitle className="text-sm">Recovery boundary</CardTitle>
            <CardDescription>Select one organization domain. Recovery never changes its identity or bundle sequence.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-[1fr_auto]">
            <NativeSelect aria-label="Trust domain to recover" value={domainId} onChange={(event) => {
              setDomainId(event.target.value);
              setPreview(null);
              setPolicyStatement(null);
              setReanchorStatement(null);
              setPolicyProviderId("");
              setReanchorNextProviderId("");
              setReanchorTrusteeProviderIds([]);
            }}>
              <NativeSelectOption value="">Select trust domain</NativeSelectOption>
              {domains.map((domain) => <NativeSelectOption key={domain.id} value={domain.id}>{domain.name} · {domain.enabled ? "enabled" : "disabled"}</NativeSelectOption>)}
            </NativeSelect>
            {selectedDomain && <Badge variant="outline" className={selectedDomain.enabled ? "border-emerald-300 text-emerald-700" : "border-red-300 text-red-700"}>{selectedDomain.enabled ? "normal" : "contained"}</Badge>}
          </CardContent>
        </Card>

        <Card className="border-[#d8dbe0] shadow-none">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm"><KeyRound className="h-4 w-4" /> External HSM/KMS signing boundary</CardTitle>
            <CardDescription>iCheck sends only a domain-separated public digest. Private keys and provider credentials stay outside the platform.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-5 xl:grid-cols-2">
            <div className="space-y-3">
              <div className="grid gap-3 md:grid-cols-2">
                <Input value={providerName} onChange={(event) => setProviderName(event.target.value)} placeholder="Provider name" />
                <NativeSelect aria-label="Signing provider kind" value={providerKind} onChange={(event) => setProviderKind(event.target.value as "hsm_gateway" | "kms_gateway")}>
                  <NativeSelectOption value="hsm_gateway">HSM gateway</NativeSelectOption>
                  <NativeSelectOption value="kms_gateway">KMS gateway</NativeSelectOption>
                </NativeSelect>
              </div>
              <Input value={providerUrl} onChange={(event) => setProviderUrl(event.target.value)} placeholder="https://recovery-signer.internal/v1/sign" />
              <Input value={signingKeyRef} onChange={(event) => setSigningKeyRef(event.target.value)} placeholder="Provider key reference / alias" />
              <NativeSelect aria-label="Signing provider public trust key" value={providerTrustKeyId} onChange={(event) => setProviderTrustKeyId(event.target.value)}>
                <NativeSelectOption value="">Pin to a local public trust key</NativeSelectOption>
                {keys.filter((key) => key.enabled && key.trust_source === "local" && key.purposes.some((purpose) => purpose === "trust_bundle" || purpose === "trust_recovery")).map((key) => (
                  <NativeSelectOption key={key.id} value={key.id}>{key.name} · {key.purposes.join(", ")}</NativeSelectOption>
                ))}
              </NativeSelect>
              <NativeSelect aria-label="Signing provider bearer credential reference" value={providerCredentialRef} onChange={(event) => setProviderCredentialRef(event.target.value)}>
                <NativeSelectOption value="">No application bearer credential</NativeSelectOption>
                {signerCredentials.map((credential) => <NativeSelectOption key={credential.id} value={credential.id}>{credential.name}</NativeSelectOption>)}
              </NativeSelect>
              <div className="grid gap-3 md:grid-cols-2">
                <NativeSelect aria-label="Initial signing provider TLS mode" value={providerTlsMode} onChange={(event) => setProviderTlsMode(event.target.value as "server_auth" | "mutual_tls")}>
                  <NativeSelectOption value="server_auth">Server-auth TLS</NativeSelectOption>
                  <NativeSelectOption value="mutual_tls">Mutual TLS</NativeSelectOption>
                </NativeSelect>
                <Input value={providerCaRef} onChange={(event) => setProviderCaRef(event.target.value)} placeholder="Optional CA credential ref" />
              </div>
              {providerTlsMode === "mutual_tls" && (
                <div className="grid gap-3 md:grid-cols-2">
                  <Input value={providerCertificateRef} onChange={(event) => setProviderCertificateRef(event.target.value)} placeholder="Client certificate ref" />
                  <Input value={providerPrivateKeyRef} onChange={(event) => setProviderPrivateKeyRef(event.target.value)} placeholder="Client private-key ref" />
                  <Input value={providerPasswordRef} onChange={(event) => setProviderPasswordRef(event.target.value)} placeholder="Optional key-password ref" />
                </div>
              )}
              <Button size="sm" disabled={!providerName.trim() || !providerUrl.trim() || !signingKeyRef.trim() || !providerTrustKeyId || (providerTlsMode === "mutual_tls" && (!providerCertificateRef.trim() || !providerPrivateKeyRef.trim())) || busy === "provider-create"} onClick={() => void registerSigningProvider()}>
                {busy === "provider-create" && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />} Register external signer
              </Button>
              <p className="text-[10px] text-muted-foreground">The HTTPS hostname must be present in <code>ICHECK_RECOVERY_SIGNING_ALLOWED_HOSTS</code>. Credential profiles must explicitly allow <code>trust_recovery_signing</code>.</p>
            </div>

            <div className="space-y-3">
              {signingProviders.length === 0 ? <p className="text-xs text-muted-foreground">No external signing providers configured.</p> : signingProviders.map((provider) => (
                <div key={provider.id} className="rounded-md border border-[#d8dbe0] bg-white p-3 text-xs">
                  <div className="flex items-start gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2"><p className="truncate font-semibold">{provider.name}</p><Badge variant="outline">{provider.provider_kind === "hsm_gateway" ? "HSM" : "KMS"}</Badge><Badge variant="outline" className={provider.enabled ? "border-emerald-300 text-emerald-700" : "border-red-300 text-red-700"}>{provider.enabled ? "enabled" : "disabled"}</Badge></div>
                      <p className="mt-1 truncate text-[10px] text-muted-foreground">{provider.url}</p>
                      <p className="mt-1 font-mono text-[9px] text-muted-foreground">key {shortHash(provider.key_fingerprint_sha256)} · {provider.tls_mode} r{provider.tls_revision} · last success {provider.last_success_at ? new Date(provider.last_success_at).toLocaleString() : "never"}</p>
                    </div>
                    <Button variant={provider.enabled ? "destructive" : "outline"} size="sm" disabled={busy === `provider-state-${provider.id}`} onClick={() => void setSigningProviderState(provider)}>{provider.enabled ? "Disable" : "Enable"}</Button>
                  </div>
                </div>
              ))}

              <div className="space-y-3 rounded-md border border-[#d8dbe0] bg-[#f7f8fa] p-3">
                <p className="text-xs font-semibold">Rotate TLS binding</p>
                <NativeSelect aria-label="Signing provider for TLS rotation" value={tlsProviderId} onChange={(event) => {
                  const id = event.target.value;
                  const provider = signingProviders.find((item) => item.id === id);
                  setTlsProviderId(id);
                  if (provider) {
                    setTlsMode(provider.tls_mode);
                    setTlsCaRef(provider.tls_ca_certificate_ref || "");
                    setTlsCertificateRef(provider.tls_client_certificate_ref || "");
                    setTlsPrivateKeyRef(provider.tls_client_private_key_ref || "");
                    setTlsPasswordRef(provider.tls_client_private_key_password_ref || "");
                  }
                }}>
                  <NativeSelectOption value="">Select provider</NativeSelectOption>
                  {signingProviders.map((provider) => <NativeSelectOption key={provider.id} value={provider.id}>{provider.name} · revision {provider.tls_revision}</NativeSelectOption>)}
                </NativeSelect>
                <div className="grid gap-3 md:grid-cols-2">
                  <NativeSelect aria-label="Rotated provider TLS mode" value={tlsMode} onChange={(event) => setTlsMode(event.target.value as "server_auth" | "mutual_tls")}>
                    <NativeSelectOption value="server_auth">Server-auth TLS</NativeSelectOption>
                    <NativeSelectOption value="mutual_tls">Mutual TLS</NativeSelectOption>
                  </NativeSelect>
                  <Input value={tlsCaRef} onChange={(event) => setTlsCaRef(event.target.value)} placeholder="Optional CA credential ref" />
                  {tlsMode === "mutual_tls" && <><Input value={tlsCertificateRef} onChange={(event) => setTlsCertificateRef(event.target.value)} placeholder="Client certificate ref" /><Input value={tlsPrivateKeyRef} onChange={(event) => setTlsPrivateKeyRef(event.target.value)} placeholder="Client private-key ref" /><Input value={tlsPasswordRef} onChange={(event) => setTlsPasswordRef(event.target.value)} placeholder="Optional key-password ref" /></>}
                </div>
                <Button variant="outline" size="sm" disabled={!tlsProviderId || (tlsMode === "mutual_tls" && (!tlsCertificateRef.trim() || !tlsPrivateKeyRef.trim())) || busy === "provider-tls"} onClick={() => void rotateSigningTLS()}>Rotate TLS references</Button>
              </div>

              <div className="space-y-2 border-t border-[#e2e5ea] pt-3">
                <p className="text-xs font-semibold">Recent verified signatures</p>
                {signingEvents.length === 0 ? <p className="text-[10px] text-muted-foreground">No gateway signatures recorded.</p> : signingEvents.slice(0, 5).map((event) => (
                  <div key={event.id} className="flex items-center gap-2 text-[10px] text-[#59677b]">
                    <Badge variant="outline">{event.document_type === "recovery_policy" ? "policy" : "re-anchor"}</Badge>
                    <span className="font-mono">{shortHash(event.signature_sha256)}</span>
                    <span>TLS r{event.tls_evidence.tls_revision ?? "—"}</span>
                    <span className="ml-auto">{new Date(event.requested_at).toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {selectedDomain && (
          <>
            <section className="grid gap-5 xl:grid-cols-2">
              <Card className="border-[#d8dbe0] shadow-none">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-sm"><KeyRound className="h-4 w-4" /> Pin recovery trustees</CardTitle>
                  <CardDescription>Dedicated local public keys only. Recovery authority cannot arrive through a routine trust bundle.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <Input value={trusteeName} onChange={(event) => setTrusteeName(event.target.value)} placeholder="recovery-trustee-east" />
                  <Textarea value={trusteePem} onChange={(event) => setTrusteePem(event.target.value)} placeholder="-----BEGIN PUBLIC KEY-----" className="min-h-24 font-mono text-[10px]" />
                  <Button size="sm" disabled={!trusteeName.trim() || !trusteePem.trim() || busy === "trustee"} onClick={() => void registerTrustee()}>
                    {busy === "trustee" && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />} Pin trustee
                  </Button>
                  <div className="space-y-2 border-t border-[#e2e5ea] pt-3">
                    {recoveryKeys.map((key) => (
                      <label key={key.id} className="flex items-center gap-2 rounded-md border border-[#d8dbe0] bg-white p-2 text-xs">
                        <input type="checkbox" checked={trusteeIds.includes(key.id)} onChange={(event) => setTrusteeIds((current) => event.target.checked ? [...current, key.id] : current.filter((id) => id !== key.id))} />
                        <span className="font-medium">{key.name}</span>
                        <span className="ml-auto font-mono text-[9px] text-muted-foreground">{shortHash(key.fingerprint_sha256)}</span>
                      </label>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card className="border-[#d8dbe0] shadow-none">
                <CardHeader>
                  <CardTitle className="text-sm">Authorize recovery policy before an incident</CardTitle>
                  <CardDescription>The current offline root signs the exact trustee set, quorum, delay, domain, and bundle head.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <Input type="number" min={2} max={8} value={requiredApprovals} onChange={(event) => setRequiredApprovals(event.target.value)} placeholder="Required approvals" />
                    <Input type="number" min={1} max={72} value={delayHours} onChange={(event) => setDelayHours(event.target.value)} placeholder="Delay hours" />
                  </div>
                  <Button variant="outline" size="sm" className="gap-2" disabled={selectedDomain.enabled === false || trusteeIds.length < 2 || busy === "policy-statement"} onClick={() => void generatePolicyStatement()}>
                    <Download className="h-3.5 w-3.5" /> Generate unsigned policy
                  </Button>
                  {policyStatement && <p className="text-[10px] text-emerald-700">Statement {shortHash(String(policyStatement.digest_sha256 || ""))} generated for offline signing.</p>}
                  {policyStatement && (
                    <div className="space-y-2 rounded-md border border-blue-200 bg-blue-50 p-3">
                      <p className="text-[10px] font-semibold text-blue-900">Optional verified HSM/KMS path</p>
                      <NativeSelect aria-label="Current-root recovery signing provider" value={policyProviderId} onChange={(event) => setPolicyProviderId(event.target.value)}>
                        <NativeSelectOption value="">Select current-root signing provider</NativeSelectOption>
                        {currentRootProviders.map((provider) => <NativeSelectOption key={provider.id} value={provider.id}>{provider.name} · {provider.provider_kind === "hsm_gateway" ? "HSM" : "KMS"}</NativeSelectOption>)}
                      </NativeSelect>
                      <Button variant="outline" size="sm" disabled={!policyProviderId || busy === "policy-sign"} onClick={() => void signPolicyWithProvider()}>
                        {busy === "policy-sign" && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />} Sign and verify with provider
                      </Button>
                    </div>
                  )}
                  <Textarea value={signedPolicyText} onChange={(event) => setSignedPolicyText(event.target.value)} placeholder="Paste current-root-signed recovery policy envelope" className="min-h-28 font-mono text-[9px]" />
                  <p className="text-[10px] text-muted-foreground">The text area remains available for air-gapped/offline signing ceremonies.</p>
                  <Input value={policyReason} onChange={(event) => setPolicyReason(event.target.value)} placeholder="Required policy reason" />
                  <Button size="sm" disabled={!signedPolicyText.trim() || !policyReason.trim() || trusteeIds.length < 2 || busy === "policy-authorize"} onClick={() => void authorizePolicy()}>
                    {busy === "policy-authorize" && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />} Authorize policy
                  </Button>
                  {activePolicy && <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-[10px] text-emerald-800">Active v{activePolicy.version}: {activePolicy.required_approvals}-of-{activePolicy.trustee_key_ids.length}, {activePolicy.delay_hours}h delay, transparency #{activePolicy.transparency_sequence}.</div>}
                </CardContent>
              </Card>
            </section>

            <Card className="border-red-200 shadow-none">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm text-red-900"><AlertTriangle className="h-4 w-4" /> Emergency ceremony</CardTitle>
                <CardDescription>Contain first. The bound checkpoint must cover the active policy and have live external witness quorum.</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-5 xl:grid-cols-2">
                <div className="space-y-3">
                  <Button variant="destructive" size="sm" disabled={!selectedDomain.enabled || !activePolicy || busy === "contain"} onClick={() => void containDomain()}>
                    Contain and disable domain
                  </Button>
                  <NativeSelect aria-label="Next pinned root for recovery" value={nextRootId} onChange={(event) => {
                    setNextRootId(event.target.value);
                    setReanchorNextProviderId("");
                    setReanchorTrusteeProviderIds([]);
                  }}>
                    <NativeSelectOption value="">Select pre-pinned next root</NativeSelectOption>
                    {rootKeys.map((key) => <NativeSelectOption key={key.id} value={key.id}>{key.name} · {shortHash(key.fingerprint_sha256)}</NativeSelectOption>)}
                  </NativeSelect>
                  <Button variant="outline" size="sm" className="gap-2" disabled={selectedDomain.enabled || !activePolicy || !nextRootId || busy === "reanchor-statement"} onClick={() => void generateReanchorStatement()}>
                    <Download className="h-3.5 w-3.5" /> Generate witnessed ceremony
                  </Button>
                  {reanchorStatement && <p className="text-[10px] text-emerald-700">Ceremony {String(reanchorStatement.ceremony_id)} ready for external signatures.</p>}
                  {reanchorStatement && (
                    <div className="space-y-2 rounded-md border border-blue-200 bg-blue-50 p-3">
                      <p className="text-[10px] font-semibold text-blue-900">Optional verified provider quorum</p>
                      <NativeSelect aria-label="Next-root recovery signing provider" value={reanchorNextProviderId} onChange={(event) => setReanchorNextProviderId(event.target.value)}>
                        <NativeSelectOption value="">Select next-root signer</NativeSelectOption>
                        {nextRootProviders.map((provider) => <NativeSelectOption key={provider.id} value={provider.id}>{provider.name}</NativeSelectOption>)}
                      </NativeSelect>
                      <div className="space-y-1">
                        {trusteeProviders.map((provider) => (
                          <label key={provider.id} className="flex items-center gap-2 rounded border border-blue-200 bg-white p-2 text-[10px]">
                            <input type="checkbox" checked={reanchorTrusteeProviderIds.includes(provider.id)} onChange={(event) => setReanchorTrusteeProviderIds((current) => event.target.checked ? [...current, provider.id] : current.filter((id) => id !== provider.id))} />
                            <span>{provider.name}</span>
                            <span className="ml-auto font-mono text-[9px] text-muted-foreground">{shortHash(provider.key_fingerprint_sha256)}</span>
                          </label>
                        ))}
                      </div>
                      <Button variant="outline" size="sm" disabled={!reanchorNextProviderId || reanchorTrusteeProviderIds.length < (activePolicy?.required_approvals || 2) || busy === "reanchor-sign"} onClick={() => void signReanchorWithProviders()}>
                        {busy === "reanchor-sign" && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />} Assemble and verify signatures
                      </Button>
                    </div>
                  )}
                </div>
                <div className="space-y-3">
                  <Textarea value={signedReanchorText} onChange={(event) => {
                    setSignedReanchorText(event.target.value);
                    setPreview(null);
                  }} placeholder="Paste envelope signed by next root and trustee quorum" className="min-h-32 font-mono text-[9px]" />
                  <p className="text-[10px] text-muted-foreground">Manual paste remains the air-gapped fallback; both paths use the same verifier and ceremony checks.</p>
                  <Button variant="outline" size="sm" className="gap-2" disabled={!signedReanchorText.trim() || !nextRootId || busy === "preview"} onClick={() => void previewReanchor()}>
                    <Eye className="h-3.5 w-3.5" /> Verify ceremony
                  </Button>
                  {preview && <div className={`rounded-md border p-3 text-xs ${preview.eligible ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-red-200 bg-red-50 text-red-800"}`}>
                    <p className="flex items-center gap-2 font-semibold">{preview.eligible ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />} {preview.eligible ? "Eligible" : "Blocked"}</p>
                    <p className="mt-1">{preview.trustee_approval_count}/{preview.required_approvals} trustees · delay {preview.execute_delay_hours}h · witnessed sequence {preview.witness_sequence}</p>
                    {preview.blockers.length > 0 && <p className="mt-1">{preview.blockers.join(" · ")}</p>}
                  </div>}
                  <Input value={reanchorReason} onChange={(event) => setReanchorReason(event.target.value)} placeholder="Required emergency reason" />
                  <Button size="sm" disabled={!preview?.eligible || !reanchorReason.trim() || busy === "propose"} onClick={() => void proposeReanchor()}>
                    {busy === "propose" && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />} Propose delayed recovery
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card className="border-[#d8dbe0] shadow-none">
              <CardHeader>
                <CardTitle className="text-sm">Recovery ledger</CardTitle>
                <CardDescription>Execution requires a different authenticated administrator and a fresh quorum-backed checkpoint after proposal.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {domainReanchors.length === 0 ? <p className="text-xs text-muted-foreground">No emergency ceremonies.</p> : domainReanchors.map((request) => (
                  <div key={request.id} className="grid gap-3 rounded-lg border border-[#d8dbe0] bg-white p-3 md:grid-cols-[1fr_auto]">
                    <div>
                      <div className="flex items-center gap-2"><p className="text-xs font-semibold">{request.ceremony_id}</p><Badge variant="outline">{request.status}</Badge></div>
                      <p className="mt-1 font-mono text-[9px] text-muted-foreground">{shortHash(request.from_key_fingerprint_sha256)} → {shortHash(request.to_key_fingerprint_sha256)}</p>
                      <p className="mt-1 text-[10px] text-muted-foreground">{request.trustee_approval_count} approvals · execute after {new Date(request.execute_after).toLocaleString()} · proposal #{request.proposal_transparency_sequence ?? "—"} · execution #{request.execution_transparency_sequence ?? "—"}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button variant="outline" size="sm" onClick={async () => downloadJson(await apiFetch<Record<string, unknown>>(`/organization-trust/root-reanchors/${request.id}/export`), `root-reanchor-${request.ceremony_id}.json`)}><Download className="h-3.5 w-3.5" /></Button>
                      {request.status === "pending" && <><Button size="sm" disabled={busy === `execute-${request.id}`} onClick={() => void actOnRequest(request, "execute")}>Execute</Button><Button variant="destructive" size="sm" disabled={busy === `cancel-${request.id}`} onClick={() => void actOnRequest(request, "cancel")}>Cancel</Button></>}
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </main>
  );
}
