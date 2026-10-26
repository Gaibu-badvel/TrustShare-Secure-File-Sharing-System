"use client";
import { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api, errMsg } from "@/lib/api";
import { Alert, Field } from "@/components/ui";

function Form() {
  const token = useSearchParams().get("token") || "";
  const [pw, setPw] = useState(""), [pw2, setPw2] = useState(""), [msg, setMsg] = useState(""), [err, setErr] = useState(""), [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr("");
    if (pw !== pw2) return setErr("Passwords do not match");
    setBusy(true);
    try { setMsg((await api.post("/api/auth/reset-password", { token, new_password: pw })).data.message); } catch (e) { setErr(errMsg(e)); } finally { setBusy(false); }
  }
  return (
    <main className="mx-auto mt-20 max-w-md px-4">
      <form onSubmit={submit} className="card">
        <h1 className="mb-4 text-xl font-semibold">Choose a new password</h1>
        {!token && <Alert>Missing reset token. Use the link from your email.</Alert>}
        <Alert>{err}</Alert><Alert kind="success">{msg}</Alert>
        <Field label="New password"><input className="input" type="password" required value={pw} onChange={(e) => setPw(e.target.value)} /></Field>
        <Field label="Confirm password"><input className="input" type="password" required value={pw2} onChange={(e) => setPw2(e.target.value)} /></Field>
        <button className="btn-primary w-full" disabled={busy || !token || !!msg}>{busy ? "Saving…" : "Update password"}</button>
      </form>
      <p className="mt-4 text-center text-sm"><Link href="/login" className="text-brand-600 hover:underline">Go to sign in</Link></p>
    </main>
  );
}
export default function Page() { return <Suspense><Form /></Suspense>; }
