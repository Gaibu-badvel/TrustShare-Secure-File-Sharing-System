"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, errMsg, fmtBytes, fmtDate, saveBlob } from "@/lib/api";
import { Alert, Badge, Empty, Spinner, useToast } from "../ui";
import { EditModal, ShareModal, VersionsModal } from "../FileModals";

const ICON: Record<string, string> = { documents: "📄", images: "🖼️", video: "🎬", audio: "🎵", archives: "🗜️", code: "💻", other: "📁" };

export default function FilesTab({ readOnly }: { readOnly: boolean }) {
  const [files, setFiles] = useState<any[]>([]), [total, setTotal] = useState(0), [folders, setFolders] = useState<any[]>([]);
  const [folder, setFolder] = useState<string>("root"), [q, setQ] = useState(""), [cat, setCat] = useState(""), [sort, setSort] = useState("created_at"), [order, setOrder] = useState("desc"), [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true), [err, setErr] = useState(""), [uploading, setUploading] = useState(0), [drag, setDrag] = useState(false);
  const [share, setShare] = useState<any>(null), [vers, setVers] = useState<any>(null), [edit, setEdit] = useState<any>(null);
  const input = useRef<HTMLInputElement>(null);
  const { toast, el } = useToast();
  const searching = !!(q || cat);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: any = { q, category: cat, sort, order, page, size: 25 };
      if (!searching) params.folder_id = folder;
      const [f, fo] = await Promise.all([api.get("/api/files", { params }), api.get("/api/folders")]);
      setFiles(f.data.items); setTotal(f.data.total); setFolders(fo.data); setErr("");
    } catch (e) { setErr(errMsg(e)); } finally { setLoading(false); }
  }, [q, cat, sort, order, page, folder, searching]);
  useEffect(() => { const t = setTimeout(load, q ? 250 : 0); return () => clearTimeout(t); }, [load, q]);

  async function upload(list: FileList | File[]) {
    for (const f of Array.from(list)) {
      setUploading((n) => n + 1);
      const fd = new FormData(); fd.append("file", f); if (folder !== "root") fd.append("folder_id", folder);
      try { await api.post("/api/files", fd); toast(`Uploaded ${f.name} (encrypted)`); } catch (e) { toast(`${f.name}: ${errMsg(e)}`, "error"); }
      setUploading((n) => n - 1);
    }
    load();
  }
  const sub = folders.filter((f) => (f.parent_id || "root") === folder);
  const crumbs: any[] = []; for (let c = folders.find((f) => f.id === folder); c; c = folders.find((f) => f.id === c.parent_id)) crumbs.unshift(c);

  async function newFolder() {
    const name = prompt("Folder name"); if (!name) return;
    try { await api.post("/api/folders", { name, parent_id: folder === "root" ? null : folder }); load(); } catch (e) { toast(errMsg(e), "error"); }
  }
  async function delFolder(f: any) {
    if (!confirm(`Delete folder “${f.name}”? Files inside will be permanently deleted.`)) return;
    try { await api.delete(`/api/folders/${f.id}`, { params: { force: true } }); load(); } catch (e) { toast(errMsg(e), "error"); }
  }
  async function delFile(f: any) {
    if (!confirm(`Permanently delete “${f.name}” and all its versions?`)) return;
    try { await api.delete(`/api/files/${f.id}`); load(); toast("Deleted"); } catch (e) { toast(errMsg(e), "error"); }
  }
  const dl = (f: any) => saveBlob(`/api/files/${f.id}/download`, f.name).catch((e) => toast(e?.response?.status === 403 ? "Not allowed" : "Download failed", "error"));

  return (
    <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={(e) => { e.preventDefault(); setDrag(false); if (!readOnly) upload(e.dataTransfer.files); }}>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <input className="input max-w-xs" placeholder="Search files…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
        <select className="input w-auto" value={cat} onChange={(e) => { setCat(e.target.value); setPage(1); }}><option value="">All types</option>{Object.keys(ICON).map((c) => <option key={c}>{c}</option>)}</select>
        <select className="input w-auto" value={`${sort}:${order}`} onChange={(e) => { const [s, o] = e.target.value.split(":"); setSort(s); setOrder(o); }}>
          <option value="created_at:desc">Newest</option><option value="created_at:asc">Oldest</option><option value="name:asc">Name A–Z</option><option value="size:desc">Largest</option></select>
        <div className="ml-auto flex gap-2">
          {!readOnly && <><button className="btn-secondary" onClick={newFolder}>＋ Folder</button>
            <input ref={input} type="file" multiple hidden onChange={(e) => { if (e.target.files) upload(e.target.files); e.target.value = ""; }} />
            <button className="btn-primary" onClick={() => input.current?.click()}>⬆ Upload</button></>}
        </div>
      </div>
      {!searching && <div className="mb-3 flex items-center gap-1 text-sm text-slate-600">
        <button className="hover:underline" onClick={() => { setFolder("root"); setPage(1); }}>My files</button>
        {crumbs.map((c) => <span key={c.id}> / <button className="hover:underline" onClick={() => { setFolder(c.id); setPage(1); }}>{c.name}</button></span>)}</div>}
      <Alert>{err}</Alert>
      <div className={`card !p-0 overflow-hidden ${drag ? "ring-2 ring-brand-500" : ""}`}>
        {uploading > 0 && <div className="bg-brand-50 px-4 py-2 text-sm text-brand-700">Encrypting & uploading {uploading} file(s)…</div>}
        {loading && !files.length ? <div className="p-10"><Spinner /></div> : <table className="w-full"><thead className="bg-slate-50"><tr><th className="th">Name</th><th className="th">Size</th><th className="th">Version</th><th className="th">Modified</th><th /></tr></thead><tbody>
          {!searching && sub.map((f) => <tr key={f.id} className="border-t hover:bg-slate-50"><td className="td cursor-pointer font-medium" onClick={() => { setFolder(f.id); setPage(1); }}>📂 {f.name}</td><td className="td" /><td className="td" /><td className="td">{fmtDate(f.created_at)}</td>
            <td className="td text-right">{!readOnly && <button className="btn-ghost !py-1 text-red-600" onClick={() => delFolder(f)}>Delete</button>}</td></tr>)}
          {files.map((f) => <tr key={f.id} className="border-t hover:bg-slate-50">
            <td className="td"><div className="font-medium">{ICON[f.category]} {f.name}</div>{f.description && <div className="text-xs text-slate-500">{f.description}</div>}
              <div className="mt-1 flex gap-1">{(f.tags || []).map((t: string) => <Badge key={t}>{t}</Badge>)}</div></td>
            <td className="td whitespace-nowrap">{fmtBytes(f.size)}</td><td className="td">v{f.current_version}</td><td className="td whitespace-nowrap">{fmtDate(f.updated_at)}</td>
            <td className="td whitespace-nowrap text-right">
              <button className="btn-ghost !py-1" onClick={() => dl(f)}>Download</button>
              {!readOnly && <button className="btn-ghost !py-1" onClick={() => setShare(f)}>Share</button>}
              <button className="btn-ghost !py-1" onClick={() => setVers(f)}>Versions</button>
              {!readOnly && <button className="btn-ghost !py-1" onClick={() => setEdit(f)}>Edit</button>}
              {!readOnly && <button className="btn-ghost !py-1 text-red-600" onClick={() => delFile(f)}>Delete</button>}</td></tr>)}
          {!loading && !files.length && !sub.length && <tr><td colSpan={5}><Empty>{searching ? "No files match your search." : readOnly ? "Nothing here." : "Drop files here or click Upload. Everything is encrypted with AES-256 before storage."}</Empty></td></tr>}
        </tbody></table>}
      </div>
      {total > 25 && <div className="mt-3 flex items-center justify-center gap-3 text-sm"><button className="btn-secondary" disabled={page === 1} onClick={() => setPage(page - 1)}>Prev</button>
        <span>Page {page} / {Math.ceil(total / 25)}</span><button className="btn-secondary" disabled={page * 25 >= total} onClick={() => setPage(page + 1)}>Next</button></div>}
      {share && <ShareModal file={share} onClose={() => setShare(null)} />}
      {vers && <VersionsModal file={vers} canEdit={!readOnly} onClose={() => setVers(null)} onChanged={load} />}
      {edit && <EditModal file={edit} onClose={() => setEdit(null)} onSaved={load} />}
      {el}
    </div>
  );
}
