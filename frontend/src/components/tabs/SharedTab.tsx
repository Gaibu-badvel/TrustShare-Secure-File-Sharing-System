"use client";
import { useCallback, useEffect, useState } from "react";
import { api, errMsg, fmtBytes, fmtDate, saveBlob } from "@/lib/api";
import { Alert, Badge, Empty, Modal, useToast } from "../ui";
import { VersionsModal } from "../FileModals";

export default function SharedTab() {
  const [withMe, setWithMe] = useState<any[]>([]), [links, setLinks] = useState<any[]>([]), [err, setErr] = useState(""), [act, setAct] = useState<any>(null), [vers, setVers] = useState<any>(null);
  const { toast, el } = useToast();
  const load = useCallback(async () => {
    try { const [a, b] = await Promise.all([api.get("/api/files", { params: { scope: "shared" } }), api.get("/api/links")]); setWithMe(a.data.items); setLinks(b.data); }
    catch (e) { setErr(errMsg(e)); }
  }, []);
  useEffect(() => { load(); }, [load]);
  async function showActivity(l: any) { setAct({ link: l, rows: (await api.get(`/api/links/${l.id}/activity`)).data }); }
  const open = (f: any, inline: boolean) => saveBlob(`/api/files/${f.id}/download${inline ? "?inline=true" : ""}`, f.name).catch(() => toast("Not allowed", "error"));
  return (
    <div className="space-y-8">
      <Alert>{err}</Alert>
      <section><h2 className="mb-2 text-lg font-semibold">Shared with me</h2>
        <div className="card !p-0 overflow-hidden"><table className="w-full"><thead className="bg-slate-50"><tr><th className="th">File</th><th className="th">From</th><th className="th">Access</th><th className="th">Size</th><th /></tr></thead><tbody>
          {withMe.map((f) => <tr key={f.id} className="border-t"><td className="td font-medium">{f.name}</td><td className="td">{f.owner_name}</td><td className="td"><Badge>{f.permission}</Badge></td><td className="td">{fmtBytes(f.size)}</td>
            <td className="td text-right whitespace-nowrap">{f.permission !== "view" && <button className="btn-ghost !py-1" onClick={() => open(f, false)}>Download</button>}
              {f.permission === "view" && <button className="btn-ghost !py-1" onClick={() => open(f, true)}>Open</button>}
              {f.permission === "edit" && <button className="btn-ghost !py-1" onClick={() => setVers(f)}>Versions</button>}</td></tr>)}
          {!withMe.length && <tr><td colSpan={5}><Empty>Nobody has shared a file with you yet.</Empty></td></tr>}
        </tbody></table></div></section>
      <section><h2 className="mb-2 text-lg font-semibold">My share links</h2>
        <div className="card !p-0 overflow-hidden"><table className="w-full"><thead className="bg-slate-50"><tr><th className="th">File</th><th className="th">Link</th><th className="th">Status</th><th className="th">Access</th><th className="th">Expires</th><th className="th">Uses</th><th /></tr></thead><tbody>
          {links.map((l) => <tr key={l.id} className="border-t"><td className="td font-medium">{l.file_name}</td><td className="td font-mono text-xs">…{l.token_hint}{l.has_password && " 🔑"}{l.allowed_email && " ✉"}</td>
            <td className="td"><Badge kind={l.status}>{l.status}</Badge></td><td className="td">{l.permission}</td><td className="td">{l.expires_at ? fmtDate(l.expires_at) : "never"}</td>
            <td className="td">{l.download_count}{l.max_downloads ? `/${l.max_downloads}` : ""} ⬇ · {l.view_count} 👁</td>
            <td className="td text-right whitespace-nowrap"><button className="btn-ghost !py-1" onClick={() => showActivity(l)}>Activity</button>
              {l.status === "active" && <button className="btn-ghost !py-1 text-red-600" onClick={async () => { await api.delete(`/api/links/${l.id}`); load(); }}>Revoke</button>}</td></tr>)}
          {!links.length && <tr><td colSpan={7}><Empty>No links yet. Create one from the Files tab → Share.</Empty></td></tr>}
        </tbody></table></div></section>
      {act && <Modal title={`Link activity — ${act.link.file_name}`} onClose={() => setAct(null)}>
        {!act.rows.length ? <Empty>No access yet.</Empty> : <table className="w-full"><tbody>{act.rows.map((r: any, i: number) => <tr key={i} className="border-t"><td className="td">{fmtDate(r.ts)}</td><td className="td"><Badge>{r.kind}</Badge></td><td className="td font-mono text-xs">{r.ip}</td></tr>)}</tbody></table>}</Modal>}
      {vers && <VersionsModal file={vers} canEdit onClose={() => setVers(null)} onChanged={load} />}
      {el}
    </div>
  );
}
