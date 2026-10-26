"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, errMsg, tokens } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Field } from "@/components/ui";

/** Receives tokens in the URL fragment (never sent to servers/logs) after OAuth2 login. */
export default function OAuthCallback() {
  const r = useRouter(), { refreshUser, setSession } = useAuth();
  const [mfa, setMfa] = useState<string | null>(null), [code, setCode] = useState(""), [err, setErr] = useState("");
  useEffect(() => {
    const p = new URLSearchParams(window.location.hash.slice(1));
    window.history.replaceState(null, "", window.location.pathname);
    if (p.get("access_token")) { tokens.set(p.get("access_token")!, p.get("refresh_token") || undefined); refreshUser().then(() => r.replace("/dashboard")); }
    else if (p.get("mfa_token")) setMfa(p.get("mfa_token"));
    else r.replace("/login?error=oauth_failed");
  }, [r, refreshUser]);
  async function verify(e: React.FormEvent) {
    e.preventDefault(); setErr("");
    try { const { data } = await api.post("/api/auth/mfa/verify", { mfa_token: mfa, code }); setSession(data); r.replace("/dashboard"); } catch (e) { setErr(errMsg(e)); }
  }
  if (!mfa) return <main className="mt-32 text-center text-slate-500">Signing you in…</main>;
  return (
    <main className="mx-auto mt-20 max-w-md px-4"><form onSubmit={verify} className="card">
      <h1 className="mb-4 text-xl font-semibold">Two-factor verification</h1><Alert>{err}</Alert>
      <Field label="Authenticator or backup code"><input className="input" autoFocus required value={code} onChange={(e) => setCode(e.target.value)} /></Field>
      <button className="btn-primary w-full">Verify</button></form></main>
  );
}
