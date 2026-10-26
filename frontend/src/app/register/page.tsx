"use client";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, errMsg } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Field } from "@/components/ui";

export default function Register() {
  const r = useRouter(), { setSession } = useAuth();
  const [f, setF] = useState({ full_name: "", username: "", email: "", password: "" });
  const [err, setErr] = useState(""), [busy, setBusy] = useState(false);
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  const checks = [[f.password.length >= 8, "8+ characters"], [/[a-z]/.test(f.password), "lowercase"], [/[A-Z]/.test(f.password), "uppercase"], [/\d/.test(f.password), "digit"]];

  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(""); setBusy(true);
    try {
      await api.post("/api/auth/register", f);
      const { data } = await api.post("/api/auth/login", { email: f.email, password: f.password });
      setSession(data); r.push("/dashboard");
    } catch (e) { setErr(errMsg(e)); } finally { setBusy(false); }
  }
  return (
    <main className="mx-auto mt-12 max-w-md px-4">
      <Link href="/" className="mb-6 block text-center text-2xl font-bold text-brand-700">🔐 TrustShare</Link>
      <form onSubmit={submit} className="card">
        <h1 className="mb-4 text-xl font-semibold">Create your account</h1>
        <Alert>{err}</Alert>
        <Field label="Full name"><input className="input" value={f.full_name} onChange={set("full_name")} /></Field>
        <Field label="Username"><input className="input" required minLength={3} pattern="[A-Za-z0-9_.\-]+" value={f.username} onChange={set("username")} /></Field>
        <Field label="Email"><input className="input" type="email" required value={f.email} onChange={set("email")} /></Field>
        <Field label="Password"><input className="input" type="password" required value={f.password} onChange={set("password")} /></Field>
        <div className="mb-4 flex flex-wrap gap-2 text-xs">{checks.map(([ok, t]: any) => <span key={t} className={ok ? "text-emerald-600" : "text-slate-400"}>{ok ? "✓" : "○"} {t}</span>)}</div>
        <button className="btn-primary w-full" disabled={busy || checks.some((c) => !c[0])}>{busy ? "Creating…" : "Create account"}</button>
      </form>
      <p className="mt-4 text-center text-sm text-slate-600">Already registered? <Link href="/login" className="text-brand-600 hover:underline">Sign in</Link></p>
    </main>
  );
}
