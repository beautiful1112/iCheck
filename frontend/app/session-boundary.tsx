"use client";

import { useEffect, useState } from "react";

import { NAMESPACE_KEY, SESSION_CHANGE_KEY } from "@/lib/icheck-api";

export default function SessionBoundary({ children }: { children: React.ReactNode }) {
  const [navigating, setNavigating] = useState(false);

  useEffect(() => {
    let navigationStarted = false;
    const changed = (event: StorageEvent) => {
      if (navigationStarted) return;
      if (event.key === SESSION_CHANGE_KEY) {
        navigationStarted = true;
        setNavigating(true);
        const destination = event.newValue?.startsWith("login:") ? "/" : "/login";
        window.location.replace(destination);
      } else if (event.key === NAMESPACE_KEY || event.key === null) {
        navigationStarted = true;
        setNavigating(true);
        window.location.reload();
      }
    };
    window.addEventListener("storage", changed);
    return () => window.removeEventListener("storage", changed);
  }, []);

  if (navigating) {
    return (
      <main className="grid min-h-screen place-items-center bg-[#f5f6f8] text-sm text-slate-600" role="status">
        Refreshing operator session…
      </main>
    );
  }
  return children;
}
