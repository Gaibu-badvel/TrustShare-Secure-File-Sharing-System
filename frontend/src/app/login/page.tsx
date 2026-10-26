"use client";
import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { API, api, errMsg } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Field } from "@/components/ui";

const ERR: Record<string, string> = { oauth_denied: "Sign-in was cancelled.", oauth_state: "Sign-in expired, please retry.", oauth_failed: "The provider rejected the sign-in.",
  oauth_no_email: "Your provider account has no verified email.", disabled: "This account is disabled." };

function LoginForm() {
  const r = useRouter(), sp = useSearchParams(), { setSession, user } = useAuth();
  const [email, setEmail] = useState(""), [password, setPassword] = useState(""), [code, setCode] = useState("");
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [err, setErr] = useState(ERR[sp.get("error") || ""] || ""), [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<Record<string, boolean>>({});
  useEffect(() => { api.get("/api/auth/oauth/providers").then((x) => setProviders(x.data)).catch(() => {}); }, []);
  useEffect(() => { if (user) r.replace("/dashboard"); }, [user, r]);

  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(""); setBusy(true);
    try {
      if (!mfaToken) {
        const { data } = await api.post("/api/auth/login", { email, password });
        if (data.mfa_required) setMfaToken(data.mfa_token); else { setSession(data); r.push("/dashboard"); }
      } else {
        const { data } = await api.post("/api/auth/mfa/verify", { mfa_token: mfaToken, code });
        setSession(data); r.push("/dashboard");
      }
    } catch (e) { setErr(errMsg(e)); } finally { setBusy(false); }
  }
  return (
    <main className="mx-auto mt-16 max-w-md px-4">
      <Link href="/" className="mb-6 block text-center text-2xl font-bold text-brand-700">🔐 TrustShare</Link>
      <form onSubmit={submit} className="card">
        <h1 className="mb-4 text-xl font-semibold">{mfaToken ? "Two-factor verification" : "Sign in"}</h1>
        <Alert>{err}</Alert>
        {!mfaToken ? <>
          <Field label="Email"><input className="input" type="email" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
          <Field label="Password"><input className="input" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
          <div className="mb-4 text-right text-sm"><Link className="text-brand-600 hover:underline" href="/forgot-password">Forgot password?</Link></div>
        </> : <>
          <p className="mb-3 text-sm text-slate-600">Enter the 6-digit code from your authenticator app, or a backup code.</p>
          <Field label="Verification code"><input className="input text-center text-lg tracking-widest" autoFocus required value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" autoComplete="one-time-code" /></Field>
        </>}
        <button className="btn-primary w-full" disabled={busy}>{busy ? "Please wait…" : mfaToken ? "Verify" : "Sign in"}</button>
        {!mfaToken && (providers.google || providers.github) && <div className="mt-4 space-y-2 border-t pt-4">
          {providers.google && <a className="btn-secondary w-full" href={`${API}/api/auth/oauth/google/login`}>Continue with Google</a>}
          {providers.github && <a className="btn-secondary w-full" href={`${API}/api/auth/oauth/github/login`}>Continue with GitHub</a>}
        </div>}
      </form>
      <p className="mt-4 text-center text-sm text-slate-600">New here? <Link href="/register" className="text-brand-600 hover:underline">Create an account</Link></p>
    </main>
  );
}
export default function Page() { return <Suspense><LoginForm /></Suspense>; }
