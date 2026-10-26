"use client";
import { useState } from "react";
import { api, errMsg } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Alert, Badge, Field, Modal } from "../ui";

export default function SettingsTab() {
  const { user, refreshUser } = useAuth();
  const [name, setName] = useState(user.full_name || ""), [notify, setNotify] = useState(user.notify_email), [msg, setMsg] = useState(""), [err, setErr] = useState("");
  const [pw, setPw] = useState({ current_password: "", new_password: "" });
  const [setup, setSetup] = useState<any>(null), [code, setCode] = useState(""), [backup, setBackup] = useState<string[] | null>(null), [dis, setDis] = useState<any>(null);
  const ok = (m: string) => { setMsg(m); setErr(""); }, bad = (e: any) => { setErr(errMsg(e)); setMsg(""); };

  return (
    <div className="max-w-2xl space-y-5">
      <Alert>{err}</Alert><Alert kind="success">{msg}</Alert>
      <form className="card" onSubmit={async (e) => { e.preventDefault(); try { await api.patch("/api/auth/me", { full_name: name, notify_email: notify }); await refreshUser(); ok("Profile saved"); } catch (e) { bad(e); } }}>
        <h3 className="mb-3 font-semibold">Profile</h3>
        <div className="mb-3 text-sm text-slate-600">{user.email} · @{user.username} · <Badge kind={user.role === "admin" ? "admin" : undefined}>{user.role}</Badge></div>
        <Field label="Full name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <label className="mb-4 flex items-center gap-2 text-sm"><input type="checkbox" checked={notify} onChange={(e) => setNotify(e.target.checked)} /> Send me email notifications (shares, downloads, security alerts)</label>
        <button className="btn-primary">Save</button>
      </form>

      <div className="card"><div className="mb-2 flex items-center justify-between"><h3 className="font-semibold">Multi-factor authentication</h3><Badge kind={user.mfa_enabled ? "ok" : "medium"}>{user.mfa_enabled ? "enabled" : "off"}</Badge></div>
        <p className="mb-3 text-sm text-slate-600">Protect your account with a time-based code from an authenticator app (Google Authenticator, Authy, 1Password…).</p>
        {!user.mfa_enabled ? <button className="btn-primary" onClick={async () => { try { setSetup((await api.post("/api/auth/mfa/setup")).data); setCode(""); } catch (e) { bad(e); } }}>Set up MFA</button>
          : <button className="btn-danger" onClick={() => setDis({ password: "", code: "" })}>Disable MFA</button>}</div>

      {!user.oauth_provider || true ? <form className="card" onSubmit={async (e) => { e.preventDefault(); try { await api.post("/api/auth/change-password", { ...pw, token: "" }); setPw({ current_password: "", new_password: "" }); ok("Password changed"); } catch (e) { bad(e); } }}>
        <h3 className="mb-3 font-semibold">Change password</h3>
        <Field label="Current password"><input className="input" type="password" required value={pw.current_password} onChange={(e) => setPw({ ...pw, current_password: e.target.value })} /></Field>
        <Field label="New password"><input className="input" type="password" required value={pw.new_password} onChange={(e) => setPw({ ...pw, new_password: e.target.value })} /></Field>
        <button className="btn-primary">Update password</button></form> : null}

      {setup && <Modal title="Set up authenticator" onClose={() => setSetup(null)}>
        <p className="mb-3 text-sm">Scan this QR code with your authenticator app, then enter the 6-digit code.</p>
        <img alt="MFA QR code" className="mx-auto mb-2 h-48 w-48" src={`data:image/png;base64,${setup.qr_png_base64}`} />
        <p className="mb-3 break-all text-center font-mono text-xs text-slate-500">Manual key: {setup.secret}</p>
        <form onSubmit={async (e) => { e.preventDefault(); try { const r = await api.post("/api/auth/mfa/enable", { code }); setSetup(null); setBackup(r.data.backup_codes); await refreshUser(); } catch (e) { bad(e); } }}>
          <input className="input mb-3 text-center text-lg tracking-widest" required autoFocus placeholder="123456" value={code} onChange={(e) => setCode(e.target.value)} /><button className="btn-primary w-full">Enable MFA</button></form></Modal>}
      {backup && <Modal title="Save your backup codes" onClose={() => setBackup(null)}>
        <p className="mb-3 text-sm text-slate-600">Each code works once if you lose your device. Store them somewhere safe — they won&apos;t be shown again.</p>
        <div className="grid grid-cols-2 gap-2 rounded-lg bg-slate-50 p-4 font-mono text-sm">{backup.map((c) => <div key={c}>{c}</div>)}</div>
        <button className="btn-secondary mt-3" onClick={() => navigator.clipboard?.writeText(backup.join("\n"))}>Copy all</button></Modal>}
      {dis && <Modal title="Disable MFA" onClose={() => setDis(null)}>
        <form onSubmit={async (e) => { e.preventDefault(); try { await api.post("/api/auth/mfa/disable", dis); setDis(null); await refreshUser(); ok("MFA disabled"); } catch (e) { bad(e); setDis(null); } }}>
          <Field label="Password"><input className="input" type="password" value={dis.password} onChange={(e) => setDis({ ...dis, password: e.target.value })} /></Field>
          <Field label="Authenticator or backup code"><input className="input" required value={dis.code} onChange={(e) => setDis({ ...dis, code: e.target.value })} /></Field>
          <button className="btn-danger">Disable</button></form></Modal>}
    </div>
  );
}
