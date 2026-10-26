"use client";
import Link from "next/link";
import { useAuth } from "@/lib/auth";

const features = [
  ["AES-256 encryption", "Every file gets its own key; only ciphertext reaches cloud storage."],
  ["Secure sharing links", "Expiry, download limits, passwords, email locks and instant revocation."],
  ["MFA + OAuth2", "TOTP authenticator codes, backup codes, Google and GitHub sign-in."],
  ["Audit & alerts", "Every access is logged; suspicious activity triggers security warnings."],
  ["Versioning & folders", "Keep history, restore any version, organise and search quickly."],
  ["Analytics dashboards", "Storage, sharing and security insights for users and admins."],
];

export default function Home() {
  const { user } = useAuth();
  return (
    <main className="mx-auto max-w-5xl px-6 py-16">
      <nav className="mb-16 flex items-center justify-between">
        <span className="text-xl font-bold text-brand-700">🔐 TrustShare</span>
        <div className="flex gap-2">
          {user ? <Link href="/dashboard" className="btn-primary">Open dashboard</Link> : <>
            <Link href="/login" className="btn-secondary">Sign in</Link><Link href="/register" className="btn-primary">Get started</Link></>}
        </div>
      </nav>
      <h1 className="text-5xl font-extrabold tracking-tight text-slate-900">Share files <span className="text-brand-600">securely</span>,<br />know exactly who accessed them.</h1>
      <p className="mt-5 max-w-2xl text-lg text-slate-600">Upload, encrypt, and share documents with temporary links and fine-grained permissions — with full audit logging and real-time security alerts.</p>
      <div className="mt-8 flex gap-3"><Link href="/register" className="btn-primary !px-6 !py-3">Create free account</Link><Link href="/login" className="btn-secondary !px-6 !py-3">Sign in</Link></div>
      <div className="mt-16 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {features.map(([t, d]) => <div key={t} className="card"><h3 className="font-semibold text-slate-900">{t}</h3><p className="mt-1 text-sm text-slate-600">{d}</p></div>)}
      </div>
    </main>
  );
}
