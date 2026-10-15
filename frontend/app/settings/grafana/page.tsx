import Link from "next/link";
import {GrafanaSettings} from "@/components/grafana-settings";

export default function GrafanaSettingsPage() {
  return <main className="mx-auto max-w-3xl space-y-5 p-6"><Link href="/" className="text-sm text-violet-700 underline">AI Operator</Link>
    <h1 className="text-2xl font-semibold">Grafana settings</h1><GrafanaSettings /></main>;
}
