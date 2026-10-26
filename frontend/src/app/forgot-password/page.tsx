"use client";
import { useState } from "react";
import Link from "next/link";
import { api, errMsg } from "@/lib/api";
import { Alert, Field } from "@/components/ui";

export default function Forgot() {
  const [email, setEmail] = useState(""), [msg, setMsg] = useState(""), [err, setErr] = useState(""), [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(""); setMsg(""); setBusy(true);
    try { setMsg((await api.post("/api/auth/forgot-password", { email })).data.message); } catch (e) { setErr(errMsg(e)); } finally { setBusy(false); }
  }
  return (
    <main className="mx-auto mt-20 max-w-md px-4">
      <form onSubmit={submit} className="card">
        <h1 className="mb-2 text-xl font-semibold">Reset your password</h1>
        <p className="mb-4 text-sm text-slate-600">We&apos;ll email you a link that is valid for 30 minutes.</p>
        <Alert>{err}</Alert><Alert kind="success">{msg}</Alert>
        <Field label="Email"><input className="input" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
        <button className="btn-primary w-full" disabled={busy}>{busy ? "Sending…" : "Send reset link"}</button>
      </form>
      <p className="mt-4 text-center text-sm"><Link href="/login" className="text-brand-600 hover:underline">Back to sign in</Link></p>
    </main>
  );
}
