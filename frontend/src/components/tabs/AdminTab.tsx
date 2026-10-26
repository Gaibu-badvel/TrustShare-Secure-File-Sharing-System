"use client";
import { useCallback, useEffect, useState } from "react";
import { api, errMsg, fmtBytes, fmtDate } from "@/lib/api";
import { Alert, Badge, Empty, Spinner, useToast } from "../ui";
import { Stat } from "./AnalyticsTab";
import SecurityTab from "./SecurityTab";

export default function AdminTab() {
  const [sec, setSec] = useState<"overview" | "users" | "security" | "keys" | "system">("overview");
  const [ov, setOv] = useState<any>(null), [users, setUsers] = useState<any[]>([]), [keys, setKeys] = useState<any>(null), [sys, setSys] = useState<any>(null), [met, setMet] = useState<any>(null);
  const [q, setQ] = useState(""), [err, setErr] = useState(""), [busy, setBusy] = useState(false), [rot, setRot] = useState<any>(null);
  const { toast, el } = useToast();

  const load = useCallback(async () => {
    try {
      if (sec === "overview") setOv((await api.get("/api/admin/overview")).data);
      if (sec === "users") setUsers((await api.get("/api/admin/users", { params: { q } })).data);
      if (sec === "keys") setKeys((await api.get("/api/admin/keys")).data);
      if (sec === "system") { const [a, b] = await Promise.all([api.get("/api/admin/system"), api.get("/api/admin/metrics")]); setSys(a.data); setMet(b.data); }
      setErr("");
    } catch (e) { setErr(errMsg(e)); }
  }, [sec, q]);
  useEffect(() => { const t = setTimeout(load, q ? 250 : 0); return () => clearTimeout(t); }, [load, q]);

  const patch = async (id: string, body: any) => { try { await api.patch(`/api/admin/users/${id}`, body); load(); } catch (e) { toast(errMsg(e), "error"); } };
  async function rotate(reencrypt: boolean) {
    if (!confirm(reencrypt ? "Create a new master key AND re-encrypt every file with fresh data keys? This may take a while." : "Create a new master key and re-wrap all file keys?")) return;
    setBusy(true); try { setRot((await api.post("/api/admin/keys/rotate", { reencrypt })).data); load(); } catch (e) { toast(errMsg(e), "error"); } finally { setBusy(false); }
  }

  return (
    <div>
      <div className="mb-4 flex flex-wrap gap-2">{(["overview", "users", "security", "keys", "system"] as const).map((s) => <button key={s} className={sec === s ? "btn-primary" : "btn-secondary"} onClick={() => setSec(s)}>{s[0].toUpperCase() + s.slice(1)}</button>)}</div>
      <Alert>{err}</Alert>
      {sec === "overview" && (!ov ? <Spinner /> : <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Stat label="Users" value={ov.users.total} sub={`${ov.users.active} active · ${ov.users.admins} admin · ${ov.users.mfa_enabled} MFA`} />
          <Stat label="Active (24h)" value={ov.users.active_24h} sub={`${ov.users.new_7d} new this week`} />
          <Stat label="Storage" value={fmtBytes(ov.storage.total_bytes)} sub={`${ov.storage.files} files · ${ov.storage.versions} versions`} />
          <Stat label="Active share links" value={ov.sharing.links_active} sub={`${ov.sharing.downloads_24h} downloads today · ${ov.sharing.downloads_7d}/7d`} />
          <Stat label="Security events (7d)" value={ov.security.events_7d} sub={`${ov.security.open} open`} />
          <Stat label="Failed logins (24h)" value={ov.security.failed_logins_24h} />
          <Stat label="Active sessions" value={ov.security.active_sessions} />
        </div>
        <div className="card"><h3 className="mb-2 font-semibold">Top storage users</h3>{ov.storage.top_users.length ? ov.storage.top_users.map((u: any) => <div key={u.user_id} className="flex justify-between text-sm"><span>{u.username}</span><b>{fmtBytes(u.bytes)}</b></div>) : <Empty>No data</Empty>}</div>
      </div>)}
      {sec === "users" && <><input className="input mb-3 max-w-xs" placeholder="Search users…" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="card !p-0 overflow-x-auto"><table className="w-full"><thead className="bg-slate-50"><tr><th className="th">User</th><th className="th">Role</th><th className="th">Storage</th><th className="th">MFA</th><th className="th">Last login</th><th className="th">Status</th><th /></tr></thead><tbody>
          {users.map((u) => <tr key={u.id} className="border-t"><td className="td"><b>{u.username}</b><div className="text-xs text-slate-500">{u.email}</div></td>
            <td className="td"><select className="input !w-auto !py-1" value={u.role} onChange={(e) => patch(u.id, { role: e.target.value })}><option>admin</option><option>user</option><option>viewer</option></select></td>
            <td className="td">{fmtBytes(u.used_bytes)} / {fmtBytes(u.quota_bytes)}</td><td className="td">{u.mfa_enabled ? "✓" : "—"}</td><td className="td">{fmtDate(u.last_login_at)}</td>
            <td className="td">{u.locked && <Badge kind="high">locked</Badge>} <Badge kind={u.is_active ? "active" : "revoked"}>{u.is_active ? "active" : "disabled"}</Badge></td>
            <td className="td whitespace-nowrap text-right">{u.locked && <button className="btn-ghost !py-1" onClick={() => patch(u.id, { unlock: true })}>Unlock</button>}
              <button className="btn-ghost !py-1" onClick={() => { const v = prompt("Quota in MB", String(Math.round(u.quota_bytes / 1048576))); if (v) patch(u.id, { quota_mb: +v }); }}>Quota</button>
              <button className="btn-ghost !py-1 text-red-600" onClick={() => patch(u.id, { is_active: !u.is_active })}>{u.is_active ? "Disable" : "Enable"}</button></td></tr>)}
        </tbody></table></div></>}
      {sec === "security" && <SecurityTab scope="all" />}
      {sec === "keys" && (!keys ? <Spinner /> : <div className="space-y-4">
        <div className="card"><h3 className="font-semibold">Encryption key management</h3><p className="mt-1 text-sm text-slate-600">{keys.algorithm}. Each file has its own key, wrapped by a versioned master key. Keys are never exposed through the API.</p>
          <div className="mt-3 flex gap-6 text-sm"><div>Active master key: <b>v{keys.active_version}</b></div><div>Versions: {keys.versions.map((v: number) => `v${v}`).join(", ")}</div></div>
          <div className="mt-2 text-sm">Blobs per key version: {Object.entries(keys.blobs_per_key_version).map(([k, v]: any) => <Badge key={k}>{`v${k}: ${v}`}</Badge>)}</div>
          <div className="mt-4 flex gap-2"><button className="btn-primary" disabled={busy} onClick={() => rotate(false)}>Rotate master key (re-wrap)</button><button className="btn-secondary" disabled={busy} onClick={() => rotate(true)}>Rotate + re-encrypt all files</button></div></div>
        {rot && <Alert kind="success">Rotated to v{rot.new_version}: {rot.rewrapped} re-wrapped, {rot.reencrypted} re-encrypted.{rot.add_to_MASTER_KEYS && <> <b>Add to MASTER_KEYS:</b> <code className="break-all">{rot.add_to_MASTER_KEYS}</code></>}</Alert>}</div>)}
      {sec === "system" && (!sys ? <Spinner /> : <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-3">{[["Database", `${sys.database.engine}`, sys.database.ok], ["Storage", sys.storage.backend, sys.storage.ok], ["Cache", sys.cache.backend, true], ["Audit log", sys.audit.backend, true], ["Email", sys.email.mode, true]].map(([n, v, ok]: any) =>
          <div key={n} className="card flex items-center justify-between"><div><div className="text-xs uppercase text-slate-500">{n}</div><div className="font-semibold">{v}</div></div><Badge kind={ok ? "ok" : "high"}>{ok ? "healthy" : "down"}</Badge></div>)}</div>
        <div className="card"><h3 className="mb-2 font-semibold">Performance metrics</h3>
          {met && Object.keys(met.timings).length ? <table className="w-full"><thead><tr><th className="th">Metric</th><th className="th">Count</th><th className="th">Avg ms</th><th className="th">p95 ms</th><th className="th">Max ms</th></tr></thead><tbody>
            {Object.entries(met.timings).map(([k, v]: any) => <tr key={k} className="border-t"><td className="td font-mono text-xs">{k}</td><td className="td">{v.count}</td><td className="td">{v.avg_ms}</td><td className="td">{v.p95_ms}</td><td className="td">{v.max_ms}</td></tr>)}</tbody></table> : <Empty>No samples yet.</Empty>}</div>
        <button className="btn-secondary" onClick={async () => { const r = await api.post("/api/admin/reminders/run"); toast(`${r.data.sent} expiry reminder(s) sent`); }}>Run expiry reminders now</button></div>)}
      {el}
    </div>
  );
}
