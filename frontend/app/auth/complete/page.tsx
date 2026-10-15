"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import {
  API_URL,
  announceBrowserSessionChange,
  clearApiNamespace,
} from "@/lib/icheck-api";

export default function CompleteBrowserLoginPage() {
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void fetch(API_URL + "/auth/me", {
      credentials: "include",
      cache: "no-store",
      signal: controller.signal,
    }).then((response) => {
      if (!response.ok || controller.signal.aborted) throw new Error("Browser sign-in was not completed");
      announceBrowserSessionChange("login");
      clearApiNamespace();
      window.location.replace("/");
    }).catch(() => {
      if (!controller.signal.aborted) setFailed(true);
    });
    return () => controller.abort();
  }, []);

  return (
    <main className="grid min-h-screen place-items-center bg-[#f5f6f8] px-4 text-slate-900">
      <section className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-7 shadow-sm">
        <h1 className="text-xl font-semibold">Completing operator sign-in</h1>
        {failed ? (
          <p className="mt-4 text-sm text-red-700" role="alert">
            The session could not be verified. <Link className="underline" href="/login">Return to sign-in</Link>.
          </p>
        ) : (
          <p className="mt-4 text-sm text-slate-600" role="status">Checking the new browser session…</p>
        )}
      </section>
    </main>
  );
}
