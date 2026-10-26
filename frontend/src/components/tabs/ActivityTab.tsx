"use client";
import { useEffect, useState } from "react";
import { api, errMsg, fmtDate } from "@/lib/api";
import { Alert, Badge, Empty } from "../ui";

export default function ActivityTab() {
  const [view, setView] = useState<"access" | "audit" | "logins">("access");
  const [rows, setRows] = useState<any[]>([]), [err, setErr] = useState(""), [prefix, setPrefix] = useState("");
  useEffect(() => {
    const url = view === "access" ? "/api/monitor/downloads" : view === "audit" ? "/api/monitor/audit" : "/api/monitor/logins";
    api.get(url, { params: view === "audit" ? { action: prefix, limit: 100 } : {} }).then((r) => { setRows(view === "audit" ? r.data.items : r.data); setErr(""); }).catch((e) => setErr(errMsg(e)));
  }, [view, prefix]);
  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {([["access", "File access"], ["audit", "Audit log"], ["logins", "Login activity"]] as const).map(([k, l]) => <button key={k} onClick={() => setView(k)} className={view === k ? "btn-primary" : "btn-secondary"}>{l}</button>)}
        {view === "audit" && <select className="input ml-auto w-auto" value={prefix} onChange={(e) => setPrefix(e.target.value)}><option value="">All actions</option>
          {["auth.", "file.", "folder.", "share.", "security.", "admin."].map((p) => <option key={p} value={p}>{p}*</option>)}</select>}
      </div>
      <Alert>{err}</Alert>
      <div className="card !p-0 overflow-x-auto">
        {view === "access" && <table className="w-full"><thead className="bg-slate-50"><tr><th className="th">Time</th><th className="th">File</th><th className="th">Event</th><th className="th">Via</th><th className="th">IP</th></tr></thead><tbody>
          {rows.map((r, i) => <tr key={i} className="border-t"><td className="td whitespace-nowrap">{fmtDate(r.ts)}</td><td className="td font-medium">{r.file_name} <span className="text-slate-400">v{r.version}</span></td><td className="td"><Badge>{r.kind}</Badge></td><td className="td">{r.via_link ? "share link" : "account"}</td><td className="td font-mono text-xs">{r.ip}</td></tr>)}</tbody></table>}
        {view === "audit" && <table className="w-full"><thead className="bg-slate-50"><tr><th className="th">Time</th><th className="th">Action</th><th className="th">Severity</th><th className="th">IP</th><th className="th">Details</th></tr></thead><tbody>
          {rows.map((r, i) => <tr key={i} className="border-t"><td className="td whitespace-nowrap">{fmtDate(r.ts)}</td><td className="td font-mono text-xs">{r.action}</td><td className="td"><Badge kind={r.severity}>{r.severity}</Badge></td><td className="td font-mono text-xs">{r.ip}</td>
            <td className="td max-w-xs truncate text-xs text-slate-500" title={JSON.stringify(r.details)}>{Object.entries(r.details || {}).map(([k, v]) => `${k}=${v}`).join(" ")}</td></tr>)}</tbody></table>}
        {view === "logins" && <table className="w-full"><thead className="bg-slate-50"><tr><th className="th">Time</th><th className="th">Result</th><th className="th">Method</th><th className="th">IP</th><th className="th">Device</th></tr></thead><tbody>
          {rows.map((r, i) => <tr key={i} className="border-t"><td className="td whitespace-nowrap">{fmtDate(r.ts)}</td><td className="td"><Badge kind={r.success ? "ok" : "high"}>{r.success ? "success" : `failed ${r.reason}`}</Badge></td><td className="td">{r.method}</td><td className="td font-mono text-xs">{r.ip}</td><td className="td max-w-xs truncate text-xs text-slate-500">{r.user_agent}</td></tr>)}</tbody></table>}
        {!rows.length && <Empty>Nothing recorded yet.</Empty>}
      </div>
    </div>
  );
}
