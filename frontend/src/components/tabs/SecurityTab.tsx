"use client";
import { useCallback, useEffect, useState } from "react";
import { api, errMsg, fmtDate } from "@/lib/api";
import { Alert, Badge, Bars, Empty, Spinner } from "../ui";
import { Stat } from "./AnalyticsTab";

export default function SecurityTab({ scope = "me" }: { scope?: "me" | "all" }) {
  const [d, setD] = useState<any>(null), [events, setEvents] = useState<any[]>([]), [sessions, setSessions] = useState<any[]>([]), [err, setErr] = useState("");
  const load = useCallback(async () => {
    try {
      const [a, b, c] = await Promise.all([api.get("/api/analytics/security", { params: { scope } }), api.get("/api/monitor/security-events", { params: { scope } }), scope === "me" ? api.get("/api/auth/sessions") : Promise.resolve({ data: [] })]);
      setD(a.data); setEvents(b.data); setSessions(c.data);
    } catch (e) { setErr(errMsg(e)); }
  }, [scope]);
  useEffect(() => { load(); }, [load]);
  if (err) return <Alert>{err}</Alert>;
  if (!d) return <Spinner />;
  return (
    <div className="space-y-5">
      <h2 className="text-lg font-semibold">Security dashboard {scope === "all" && <Badge kind="admin">all users</Badge>}</h2>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Successful logins" value={d.logins.success} sub="last 30 days" /><Stat label="Failed logins" value={d.logins.failed} />
        <Stat label="Unauthorized attempts" value={d.unauthorized_attempts} /><Stat label="Open security events" value={d.open_events} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="card"><h3 className="mb-2 font-semibold">Logins per day <span className="ml-2 text-xs font-normal text-slate-500"><span className="text-emerald-600">■</span> ok <span className="text-red-500">■</span> failed</span></h3><Bars data={d.logins.per_day} x="date" ys={["success", "failed"]} colors={["#10b981", "#ef4444"]} /></div>
        <div className="card"><h3 className="mb-2 font-semibold">Events by severity</h3>
          {Object.keys(d.events_by_severity).length ? <div className="flex flex-wrap gap-2">{Object.entries(d.events_by_severity).map(([k, v]: any) => <span key={k}><Badge kind={k}>{k}</Badge> <b>{v}</b></span>)}</div> : <Empty>No events 🎉</Empty>}
          <h4 className="mb-1 mt-4 text-sm font-semibold">Top failed-login IPs</h4>
          {d.top_failed_ips.length ? d.top_failed_ips.map(([ip, n]: any) => <div key={ip} className="flex justify-between font-mono text-xs"><span>{ip}</span><span>{n}</span></div>) : <div className="text-sm text-slate-400">None</div>}</div>
      </div>
      <div className="card !p-0 overflow-x-auto"><div className="p-4 pb-2 font-semibold">Security events</div>
        <table className="w-full"><thead className="bg-slate-50"><tr><th className="th">Time</th><th className="th">Type</th><th className="th">Severity</th><th className="th">Message</th><th /></tr></thead><tbody>
          {events.map((e) => <tr key={e.id} className="border-t"><td className="td whitespace-nowrap">{fmtDate(e.ts)}</td><td className="td font-mono text-xs">{e.type}</td><td className="td"><Badge kind={e.severity}>{e.severity}</Badge></td><td className="td">{e.message}</td>
            <td className="td text-right">{e.resolved ? <Badge kind="ok">resolved</Badge> : <button className="btn-ghost !py-1" onClick={async () => { await api.post(`/api/monitor/security-events/${e.id}/resolve`); load(); }}>Resolve</button>}</td></tr>)}
        </tbody></table>{!events.length && <Empty>No security events.</Empty>}</div>
      {scope === "me" && <div className="card !p-0 overflow-x-auto"><div className="flex items-center justify-between p-4 pb-2"><span className="font-semibold">Active sessions</span>
        <button className="btn-secondary" onClick={async () => { if (confirm("Sign out everywhere (including here)?")) { await api.post("/api/auth/logout-all"); window.location.href = "/login"; } }}>Sign out everywhere</button></div>
        <table className="w-full"><tbody>{sessions.map((s) => <tr key={s.id} className="border-t"><td className="td">{fmtDate(s.created_at)}</td><td className="td font-mono text-xs">{s.ip}</td><td className="td max-w-xs truncate text-xs text-slate-500">{s.user_agent}</td>
          <td className="td text-right">{s.current ? <Badge kind="ok">this device</Badge> : <button className="btn-ghost !py-1 text-red-600" onClick={async () => { await api.delete(`/api/auth/sessions/${s.id}`); load(); }}>Revoke</button>}</td></tr>)}</tbody></table></div>}
    </div>
  );
}
