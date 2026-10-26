"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, errMsg, fmtBytes, fmtDate, saveBlob } from "@/lib/api";
import { Alert, Badge, Empty, Field, Modal } from "./ui";

export function ShareModal({ file, onClose }: { file: any; onClose: () => void }) {
  const [tab, setTab] = useState<"link" | "people">("link");
  const [links, setLinks] = useState<any[]>([]), [shares, setShares] = useState<any[]>([]);
  const [err, setErr] = useState(""), [created, setCreated] = useState<any>(null), [copied, setCopied] = useState(false);
  const [lf, setLf] = useState({ permission: "download", expires_in_hours: "24", max_downloads: "", password: "", allowed_email: "", note: "" });
  const [sf, setSf] = useState({ email: "", permission: "download", expires_in_hours: "" });

  const load = useCallback(async () => {
    const [l, s] = await Promise.all([api.get(`/api/files/${file.id}/links`), api.get(`/api/files/${file.id}/shares`)]);
    setLinks(l.data); setShares(s.data);
  }, [file.id]);
  useEffect(() => { load().catch((e) => setErr(errMsg(e))); }, [load]);

  async function createLink(e: React.FormEvent) {
    e.preventDefault(); setErr(""); setCreated(null);
    try {
      const body: any = { permission: lf.permission, note: lf.note };
      body.expires_in_hours = lf.expires_in_hours ? Number(lf.expires_in_hours) : null;
      if (lf.max_downloads) body.max_downloads = Number(lf.max_downloads);
      if (lf.password) body.password = lf.password;
      if (lf.allowed_email) body.allowed_email = lf.allowed_email;
      const { data } = await api.post(`/api/files/${file.id}/links`, body);
      setCreated(data); setCopied(false); load();
    } catch (e) { setErr(errMsg(e)); }
  }
  async function addShare(e: React.FormEvent) {
    e.preventDefault(); setErr("");
    try {
      await api.post(`/api/files/${file.id}/shares`, { email: sf.email, permission: sf.permission, expires_in_hours: sf.expires_in_hours ? Number(sf.expires_in_hours) : null });
      setSf({ ...sf, email: "" }); load();
    } catch (e) { setErr(errMsg(e)); }
  }
  const revoke = async (id: string) => { await api.delete(`/api/links/${id}`); load(); };
  const unshare = async (id: string) => { await api.delete(`/api/shares/${id}`); load(); };

  return (
    <Modal title={`Share “${file.name}”`} onClose={onClose} wide>
      <div className="mb-4 flex gap-2 border-b">
        {(["link", "people"] as const).map((t) => <button key={t} onClick={() => setTab(t)} className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium ${tab === t ? "border-brand-600 text-brand-700" : "border-transparent text-slate-500"}`}>{t === "link" ? "Secure link" : "People"}</button>)}
      </div>
      <Alert>{err}</Alert>
      {tab === "link" && <>
        <form onSubmit={createLink} className="grid grid-cols-2 gap-x-3">
          <Field label="Access level"><select className="input" value={lf.permission} onChange={(e) => setLf({ ...lf, permission: e.target.value })}><option value="download">Download</option><option value="view">View only (no download)</option></select></Field>
          <Field label="Expires in (hours)"><input className="input" type="number" min="0.1" step="any" value={lf.expires_in_hours} onChange={(e) => setLf({ ...lf, expires_in_hours: e.target.value })} placeholder="blank = never" /></Field>
          <Field label="Max downloads"><input className="input" type="number" min="1" value={lf.max_downloads} onChange={(e) => setLf({ ...lf, max_downloads: e.target.value })} placeholder="unlimited" /></Field>
          <Field label="Password (optional)"><input className="input" type="text" minLength={4} value={lf.password} onChange={(e) => setLf({ ...lf, password: e.target.value })} /></Field>
          <Field label="Restrict to email (optional)"><input className="input" type="email" value={lf.allowed_email} onChange={(e) => setLf({ ...lf, allowed_email: e.target.value })} /></Field>
          <Field label="Note for recipient"><input className="input" maxLength={255} value={lf.note} onChange={(e) => setLf({ ...lf, note: e.target.value })} /></Field>
          <div className="col-span-2"><button className="btn-primary">Generate link</button></div>
        </form>
        {created && <div className="my-4 rounded-lg border border-emerald-200 bg-emerald-50 p-3">
          <p className="mb-2 text-sm font-medium text-emerald-800">Link created — copy it now, it won&apos;t be shown again.</p>
          <div className="flex gap-2"><input readOnly className="input font-mono text-xs" value={created.url} onFocus={(e) => e.target.select()} />
            <button className="btn-secondary" onClick={() => { navigator.clipboard?.writeText(created.url); setCopied(true); }}>{copied ? "Copied ✓" : "Copy"}</button></div></div>}
        <h4 className="mb-2 mt-5 text-sm font-semibold">Existing links</h4>
        {!links.length ? <Empty>No links yet</Empty> : <div className="overflow-x-auto"><table className="w-full"><thead><tr><th className="th">Link</th><th className="th">Status</th><th className="th">Access</th><th className="th">Expires</th><th className="th">Uses</th><th /></tr></thead><tbody>
          {links.map((l) => <tr key={l.id} className="border-t"><td className="td font-mono text-xs">…{l.token_hint}{l.has_password && " 🔑"}{l.allowed_email && " ✉"}</td><td className="td"><Badge kind={l.status}>{l.status}</Badge></td>
            <td className="td">{l.permission}</td><td className="td">{l.expires_at ? fmtDate(l.expires_at) : "never"}</td>
            <td className="td">{l.download_count}{l.max_downloads ? `/${l.max_downloads}` : ""} ⬇ · {l.view_count} 👁</td>
            <td className="td">{l.status === "active" && <button className="btn-ghost !py-1 text-red-600" onClick={() => revoke(l.id)}>Revoke</button>}</td></tr>)}
        </tbody></table></div>}
      </>}
      {tab === "people" && <>
        <form onSubmit={addShare} className="mb-4 grid grid-cols-6 items-end gap-2">
          <div className="col-span-3"><span className="label">User email</span><input className="input" type="email" required value={sf.email} onChange={(e) => setSf({ ...sf, email: e.target.value })} /></div>
          <div className="col-span-2"><span className="label">Access</span><select className="input" value={sf.permission} onChange={(e) => setSf({ ...sf, permission: e.target.value })}><option value="view">View</option><option value="download">Download</option><option value="edit">Edit (new versions)</option></select></div>
          <button className="btn-primary">Share</button>
        </form>
        {!shares.length ? <Empty>Not shared with anyone</Empty> : <table className="w-full"><tbody>{shares.map((s) => <tr key={s.id} className="border-t"><td className="td"><b>{s.username}</b> <span className="text-slate-500">{s.email}</span></td>
          <td className="td"><Badge>{s.permission}</Badge></td><td className="td text-xs text-slate-500">{s.expires_at ? `until ${fmtDate(s.expires_at)}` : ""}</td>
          <td className="td text-right"><button className="btn-ghost !py-1 text-red-600" onClick={() => unshare(s.id)}>Remove</button></td></tr>)}</tbody></table>}
      </>}
    </Modal>
  );
}

export function VersionsModal({ file, onClose, onChanged, canEdit }: { file: any; onClose: () => void; onChanged: () => void; canEdit: boolean }) {
  const [vs, setVs] = useState<any[]>([]), [err, setErr] = useState(""), ref = useRef<HTMLInputElement>(null);
  const load = useCallback(() => api.get(`/api/files/${file.id}/versions`).then((r) => setVs(r.data)).catch((e) => setErr(errMsg(e))), [file.id]);
  useEffect(() => { load(); }, [load]);
  async function upload(f?: File) {
    if (!f) return; setErr("");
    const fd = new FormData(); fd.append("file", f);
    try { await api.post(`/api/files/${file.id}/versions`, fd); await load(); onChanged(); } catch (e) { setErr(errMsg(e)); }
  }
  async function restore(v: number) { try { await api.post(`/api/files/${file.id}/versions/${v}/restore`); await load(); onChanged(); } catch (e) { setErr(errMsg(e)); } }
  return (
    <Modal title={`Versions — ${file.name}`} onClose={onClose} wide>
      <Alert>{err}</Alert>
      {canEdit && <div className="mb-4"><input ref={ref} type="file" hidden onChange={(e) => { upload(e.target.files?.[0]); e.target.value = ""; }} />
        <button className="btn-primary" onClick={() => ref.current?.click()}>⬆ Upload new version</button></div>}
      <table className="w-full"><thead><tr><th className="th">Version</th><th className="th">Size</th><th className="th">SHA-256</th><th className="th">Key</th><th className="th">Created</th><th /></tr></thead><tbody>
        {vs.map((v) => <tr key={v.id} className="border-t"><td className="td">v{v.version} {v.version === file.current_version && <Badge kind="active">current</Badge>}</td><td className="td">{fmtBytes(v.size)}</td>
          <td className="td font-mono text-xs">{v.sha256.slice(0, 12)}…</td><td className="td">K{v.key_version}</td><td className="td">{fmtDate(v.created_at)}</td>
          <td className="td whitespace-nowrap text-right"><button className="btn-ghost !py-1" onClick={() => saveBlob(`/api/files/${file.id}/download?version=${v.version}`, file.name).catch((e) => setErr(errMsg(e)))}>Download</button>
            {canEdit && v.version !== file.current_version && <button className="btn-ghost !py-1" onClick={() => restore(v.version)}>Restore</button>}</td></tr>)}
      </tbody></table>
    </Modal>
  );
}

export function EditModal({ file, onClose, onSaved }: { file: any; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState({ name: file.name, description: file.description || "", tags: (file.tags || []).join(", "), category: file.category });
  const [err, setErr] = useState("");
  async function save(e: React.FormEvent) {
    e.preventDefault();
    try { await api.patch(`/api/files/${file.id}`, { name: f.name, description: f.description, category: f.category, tags: f.tags.split(",").map((t) => t.trim()).filter(Boolean) }); onSaved(); onClose(); }
    catch (e) { setErr(errMsg(e)); }
  }
  return (
    <Modal title="File details" onClose={onClose}>
      <form onSubmit={save}><Alert>{err}</Alert>
        <Field label="Name"><input className="input" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label="Category"><select className="input" value={f.category} onChange={(e) => setF({ ...f, category: e.target.value })}>
          {["documents", "images", "video", "audio", "archives", "code", "other"].map((c) => <option key={c}>{c}</option>)}</select></Field>
        <Field label="Description"><textarea className="input" rows={3} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <Field label="Tags (comma separated)"><input className="input" value={f.tags} onChange={(e) => setF({ ...f, tags: e.target.value })} /></Field>
        <button className="btn-primary">Save</button></form>
    </Modal>
  );
}
