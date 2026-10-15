"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { changeOwnPassword } from "@/lib/icheck-api";

export default function AccountSettingsPage() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (newPassword !== confirmation) {
      setMessage("Passwords do not match.");
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      await changeOwnPassword(currentPassword, newPassword);
      setMessage("Password changed. Your other browser sessions have been signed out.");
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : "Unable to change password");
    } finally {
      setCurrentPassword(""); setNewPassword(""); setConfirmation(""); setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#f5f6f8] p-6 text-slate-900">
      <section className="mx-auto max-w-lg space-y-5 rounded-2xl border bg-white p-6 shadow-sm">
        <Link href="/" className="text-sm text-violet-700">Back to workspace</Link>
        <h1 className="text-xl font-semibold">Account settings</h1>
        <p className="text-sm text-muted-foreground">Change your web sign-in password. Use 15 to 256 characters. If your account uses only SSO, contact an administrator to set a local password.</p>
        <form onSubmit={changePassword} className="space-y-4">
          <label className="block space-y-1 text-sm">Current password
            <Input required name="current-password" type="password" autoComplete="current-password" maxLength={256} value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} />
          </label>
          <label className="block space-y-1 text-sm">New password
            <Input required name="new-password" type="password" autoComplete="new-password" minLength={15} maxLength={256} value={newPassword} onChange={(event) => setNewPassword(event.target.value)} />
          </label>
          <label className="block space-y-1 text-sm">Confirm new password
            <Input required name="confirm-password" type="password" autoComplete="new-password" minLength={15} maxLength={256} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} />
          </label>
          <Button disabled={busy}>{busy ? "Saving…" : "Change password"}</Button>
        </form>
        {message ? <p role="status" className="text-sm">{message}</p> : null}
      </section>
    </main>
  );
}
