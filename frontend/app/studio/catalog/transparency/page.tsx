"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Fingerprint,
  Link2,
  Loader2,
  RefreshCw,
  ShieldAlert,
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
import { apiFetch } from "@/lib/icheck-api";
import { cn } from "@/lib/utils";

type Checkpoint = {
  format_version: string;
  log_id: string;
  epoch: number;
  last_sequence: number;
  head_digest_sha256: string;
  updated_at: string;
};

type Verification = {
  valid: boolean;
  record_count: number;
  first_sequence: number | null;
  last_sequence: number;
  calculated_head_digest_sha256: string;
  stored_head_digest_sha256: string;
  failure_sequence: number | null;
};

type TransparencyRecord = {
  id: string;
  sequence: number;
  previous_digest_sha256: string;
  record_digest_sha256: string;
  event_type: string;
  entity_type: string;
  entity_id: string;
  subject_digest_sha256: string;
  details: Record<string, string | number | boolean | null>;
  occurred_at: string;
};

type RecordList = {
  items: TransparencyRecord[];
  head_sequence: number;
  head_digest_sha256: string;
};

function shortHash(value: string) {
  return `${value.slice(0, 12)}…`;
}

export default function CapabilityTransparencyPage() {
  const [checkpoint, setCheckpoint] = useState<Checkpoint | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [records, setRecords] = useState<TransparencyRecord[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setBusy(true);
    try {
      const [checkpointRow, recordRows] = await Promise.all([
        apiFetch<Checkpoint>("/capability-transparency/checkpoint"),
        apiFetch<RecordList>("/capability-transparency/records?limit=500"),
      ]);
      setCheckpoint(checkpointRow);
      setRecords(recordRows.items);
      setError(null);
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to load capability transparency records",
      );
    } finally {
      setBusy(false);
    }
  }, []);

  async function verifyChain() {
    setBusy(true);
    setError(null);
    try {
      setVerification(
        await apiFetch<Verification>("/capability-transparency/verify"),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Chain verification failed");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  return (
    <main className="min-h-screen bg-[#eef0f5] text-[#253044]">
      <header className="border-b border-[#d8dbe0] bg-white">
        <div className="mx-auto flex min-h-16 max-w-[1400px] items-center gap-3 px-5">
          <Link
            href="/studio/catalog"
            className="rounded-md p-2 text-[#59677b] hover:bg-[#eef0f5]"
            aria-label="Back to catalog"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-[#171c2a] text-white">
            <Fingerprint className="h-4 w-4" />
          </span>
          <div>
            <h1 className="text-sm font-semibold">Capability transparency</h1>
            <p className="text-xs text-muted-foreground">
              Append-only ecosystem events linked by canonical SHA-256 records
            </p>
          </div>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/remote" className="ml-auto">Remote catalogs</Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/trust">Organization trust</Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href="/studio/catalog/transparency/witnesses">External witnesses</Link>
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            disabled={busy}
            onClick={() => void verifyChain()}
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} Verify chain
          </Button>
        </div>
      </header>

      <div className="mx-auto max-w-[1400px] space-y-6 px-5 py-6">
        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-xs text-red-700">
            {error}
          </div>
        )}

        <section className="grid gap-4 md:grid-cols-3">
          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-sm">Checkpoint</CardTitle>
              <CardDescription>Current sequence and chain head.</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-semibold">{checkpoint?.last_sequence ?? "—"}</p>
              <p className="mt-2 break-all font-mono text-[9px] text-muted-foreground">
                {checkpoint?.head_digest_sha256 ?? "—"}
              </p>
            </CardContent>
          </Card>
          <Card className={cn("shadow-none", verification?.valid === false ? "border-red-300" : "border-emerald-300")}>
            <CardHeader>
              <CardTitle className="text-sm">Local chain verification</CardTitle>
              <CardDescription>Recomputed from genesis through the stored head.</CardDescription>
            </CardHeader>
            <CardContent className="flex items-center gap-3">
              {verification?.valid === false ? <ShieldAlert className="h-7 w-7 text-red-600" /> : <CheckCircle2 className="h-7 w-7 text-emerald-600" />}
              <div>
                <p className="text-sm font-semibold">{verification ? (verification.valid ? "Chain valid" : "Integrity failure") : "Not verified this session"}</p>
                <p className="text-[10px] text-muted-foreground">{verification?.record_count ?? 0} records{verification?.failure_sequence ? ` · failed at ${verification.failure_sequence}` : ""}</p>
              </div>
            </CardContent>
          </Card>
          <Card className="border-[#d8dbe0] shadow-none">
            <CardHeader>
              <CardTitle className="text-sm">Witness boundary</CardTitle>
              <CardDescription>Pin this head outside the control plane.</CardDescription>
            </CardHeader>
            <CardContent className="text-[11px] leading-5 text-[#59677b]">
              <p>
                Log {checkpoint?.log_id ?? "—"} · epoch{" "}
                {checkpoint?.epoch ?? "—"}. Publish quorum-signed checkpoints
                and compare cross-region gossip on the dedicated page.
              </p>
              <Link
                href="/studio/catalog/transparency/witnesses"
                className="mt-3 inline-flex text-violet-700 hover:underline"
              >
                Manage external witnesses
              </Link>
            </CardContent>
          </Card>
        </section>

        <Card className="border-[#d8dbe0] shadow-none">
          <CardHeader>
            <CardTitle className="text-base">Transparency records</CardTitle>
            <CardDescription>
              Catalog refreshes and key rotations, pack installs/upgrades,
              revocation feeds, and uninstalls enter the same ordered chain.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {records.length === 0 ? (
              <div className="rounded-lg border border-dashed border-[#cbd1da] p-10 text-center text-sm text-muted-foreground">
                No capability ecosystem events have been chained yet.
              </div>
            ) : records.map((record) => (
              <div key={record.id} className="rounded-lg border border-[#d8dbe0] bg-white p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex items-start gap-3">
                    <span className="grid h-8 w-8 place-items-center rounded-full bg-violet-50 text-violet-700">
                      <Link2 className="h-3.5 w-3.5" />
                    </span>
                    <div>
                      <p className="text-sm font-semibold">{record.event_type}</p>
                      <p className="mt-1 text-[10px] text-muted-foreground">
                        {record.entity_type} · {record.entity_id.slice(0, 12)}… · {new Date(record.occurred_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <Badge variant="outline" className="font-mono text-[9px]">
                    sequence {record.sequence}
                  </Badge>
                </div>
                <div className="mt-3 grid gap-1 font-mono text-[9px] text-muted-foreground md:grid-cols-3">
                  <p>previous {shortHash(record.previous_digest_sha256)}</p>
                  <p>subject {shortHash(record.subject_digest_sha256)}</p>
                  <p>record {shortHash(record.record_digest_sha256)}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
