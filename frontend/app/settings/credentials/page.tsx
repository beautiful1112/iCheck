"use client";
import Link from "next/link";
import { DeviceCredentials } from "@/components/device-credentials";
export default function CredentialsPage() {
  return <main className="min-h-screen bg-slate-50 p-4 sm:p-8"><div className="mx-auto max-w-4xl">
    <Link href="/" className="text-sm text-violet-700 underline">AI operator</Link>
    <h1 className="my-5 text-2xl font-semibold">Device credentials</h1>
    <DeviceCredentials />
    <Link href="/assets/devices" className="mt-5 inline-block text-sm text-violet-700 underline">Add devices and verify collection</Link>
  </div></main>;
}
