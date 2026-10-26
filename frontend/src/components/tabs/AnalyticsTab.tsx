"use client";
import { useEffect, useState } from "react";
import { api, errMsg, fmtBytes } from "@/lib/api";
import { Alert, Bars, Empty, Progress, Spinner } from "../ui";

export const Stat = ({ label, value, sub }: { label: string; value: any; sub?: string }) => (
  <div className="card"><div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div><div className="mt-1 text-2xl font-bold text-slate-900">{value}</div>{sub && <div className="text-xs text-slate-500">{sub}</div>}</div>
);

export default function AnalyticsTab() {
  const [d, setD] = useState<any>(null), [days, setDays] = useState(30), [err, setErr] = useState("");
  useEffect(() => { api.get("/api/analytics/files", { params: { days } }).then((r) => setD(r.data)).catch((e) => setErr(errMsg(e))); }, [days]);
  if (err) return <Alert>{err}</Alert>;
  if (!d) return <Spinner />;
  const s = d.storage, sh = d.sharing;
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between"><h2 className="text-lg font-semibold">File analytics</h2>
        <select className="input w-auto" value={days} onChange={(e) => setDays(+e.target.value)}><option value={7}>7 days</option><option value={30}>30 days</option><option value={90}>90 days</option></select></div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Storage used" value={fmtBytes(s.used_bytes)} sub={`of ${fmtBytes(s.quota_bytes)} (${s.percent}%)`} />
        <Stat label="Files" value={s.files} sub={`${s.versions} versions`} />
        <Stat label="Active links" value={sh.links_active} sub={`${sh.links_total} total · ${sh.links_revoked} revoked`} />
        <Stat label="Link downloads" value={sh.total_link_downloads} sub={`${sh.direct_shares} direct shares`} />
      </div>
      <div className="card"><Progress value={s.percent} /></div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="card"><h3 className="mb-2 font-semibold">Uploads per day</h3><Bars data={d.uploads_per_day} x="date" ys={["count"]} /></div>
        <div className="card"><h3 className="mb-2 font-semibold">Downloads &amp; views per day <span className="ml-2 text-xs font-normal text-slate-500"><span className="text-emerald-600">■</span> downloads <span className="text-indigo-500">■</span> views</span></h3><Bars data={d.downloads_per_day} x="date" ys={["downloads", "views"]} colors={["#10b981", "#6366f1"]} /></div>
        <div className="card"><h3 className="mb-2 font-semibold">Storage by category</h3>
          {d.by_category.length ? d.by_category.map((c: any) => <div key={c.category} className="mb-2"><div className="flex justify-between text-sm"><span className="capitalize">{c.category} ({c.files})</span><span>{fmtBytes(c.bytes)}</span></div><Progress value={s.used_bytes ? (c.bytes * 100) / s.used_bytes : 0} /></div>) : <Empty>No files yet</Empty>}</div>
        <div className="card"><h3 className="mb-2 font-semibold">Most downloaded</h3>
          {d.top_downloaded.length ? <ol className="space-y-1 text-sm">{d.top_downloaded.map((t: any, i: number) => <li key={t.file_id} className="flex justify-between"><span>{i + 1}. {t.name}</span><b>{t.downloads}</b></li>)}</ol> : <Empty>No downloads yet</Empty>}</div>
      </div>
    </div>
  );
}
