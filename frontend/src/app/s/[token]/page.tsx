"use client";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { API, api, errMsg, fmtBytes, fmtDate } from "@/lib/api";
import { Alert, Badge, Spinner } from "@/components/ui";

export default function SharedFile() {
  const { token } = useParams<{ token: string }>();
  const [meta, setMeta] = useState<any>(null), [err, setErr] = useState(""), [pw, setPw] = useState(""), [busy, setBusy] = useState(false), [preview, setPreview] = useState<string | null>(null), [done, setDone] = useState("");

  useEffect(() => { api.get(`/api/public/links/${token}`).then((r) => setMeta(r.data)).catch((e) => setErr(errMsg(e))); }, [token]);
  const hdr = () => (pw ? { "X-Share-Password": pw } : {});

  async function fetchFile(kind: "download" | "preview") {
    setErr(""); setBusy(true);
    try {
      const res = await api.get(`/api/public/links/${token}/${kind}`, { responseType: "blob", headers: hdr() });
      if (kind === "preview") { setPreview(URL.createObjectURL(res.data)); }
      else {
        const a = document.createElement("a"); a.href = URL.createObjectURL(res.data); a.download = meta.file_name; document.body.appendChild(a); a.click(); a.remove();
        setDone("Download started."); api.get(`/api/public/links/${token}`).then((r) => setMeta(r.data)).catch(() => {});
      }
    } catch (e: any) {
      let m = errMsg(e);
      if (e?.response?.data instanceof Blob) { try { m = JSON.parse(await e.response.data.text()).detail || m; } catch {} }
      setErr(m);
    } finally { setBusy(false); }
  }

  const canPreview = meta && /^(image\/(png|jpeg|gif|webp)|application\/pdf|text\/plain)/.test(meta.mime_type);
  return (
    <main className="mx-auto mt-16 max-w-xl px-4">
      <Link href="/" className="mb-6 block text-center text-2xl font-bold text-brand-700">🔐 TrustShare</Link>
      <div className="card">
        {!meta && !err && <Spinner />}
        {!meta && err && <><h1 className="mb-2 text-lg font-semibold">Link unavailable</h1><Alert>{err}</Alert></>}
        {meta && <>
          <div className="mb-1 flex items-center gap-2"><h1 className="break-all text-lg font-semibold">{meta.file_name}</h1><Badge kind={meta.status}>{meta.status}</Badge></div>
          <p className="mb-4 text-sm text-slate-500">{fmtBytes(meta.size)} · {meta.category} · {meta.permission === "view" ? "view only" : "download allowed"}</p>
          {meta.note && <p className="mb-3 rounded-lg bg-slate-50 p-3 text-sm">{meta.note}</p>}
          <ul className="mb-4 space-y-1 text-sm text-slate-600">
            <li>⏳ Expires: {meta.expires_at ? fmtDate(meta.expires_at) : "never"}</li>
            {meta.remaining_downloads !== null && <li>⬇ Downloads left: {meta.remaining_downloads}</li>}
            {meta.requires_login_as && <li>✉ Restricted to <b>{meta.requires_login_as}</b> — <Link className="text-brand-600 underline" href="/login">sign in</Link> first</li>}
          </ul>
          <Alert>{err}</Alert><Alert kind="success">{done}</Alert>
          {meta.requires_password && <input className="input mb-3" type="password" placeholder="Link password" value={pw} onChange={(e) => setPw(e.target.value)} />}
          <div className="flex gap-2">
            {meta.permission === "download" && <button className="btn-primary" disabled={busy} onClick={() => fetchFile("download")}>⬇ Download</button>}
            {canPreview && <button className="btn-secondary" disabled={busy} onClick={() => fetchFile("preview")}>👁 Preview</button>}
          </div>
          {preview && (meta.mime_type.startsWith("image/") ? <img src={preview} alt="preview" className="mt-4 max-h-96 rounded-lg border" /> : <iframe src={preview} sandbox="" className="mt-4 h-96 w-full rounded-lg border" title="preview" />)}
          <p className="mt-5 text-xs text-slate-400">🔒 Encrypted at rest with AES-256-GCM. Every access is logged.</p>
        </>}
      </div>
    </main>
  );
}
