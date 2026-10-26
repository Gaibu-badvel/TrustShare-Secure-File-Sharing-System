"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { api, errMsg, fmtDate } from "@/lib/api";
import { Alert, Empty } from "../ui";

const ICON: Record<string, string> = { share: "🤝", access: "👁", download: "⬇️", security: "🛡️", expiry: "⏳", system: "ℹ️" };

export default function NotificationsTab({ onChange }: { onChange: () => void }) {
  const [items, setItems] = useState<any[]>([]), [err, setErr] = useState("");
  const load = useCallback(() => api.get("/api/notifications").then((r) => { setItems(r.data.items); onChange(); }).catch((e) => setErr(errMsg(e))), [onChange]);
  useEffect(() => { load(); }, [load]);
  return (
    <div>
      <div className="mb-3 flex justify-between"><h2 className="text-lg font-semibold">Notifications</h2><button className="btn-secondary" onClick={async () => { await api.post("/api/notifications/read-all"); load(); }}>Mark all read</button></div>
      <Alert>{err}</Alert>
      <div className="card divide-y !p-0">
        {items.map((n) => <div key={n.id} className={`flex items-start gap-3 p-4 ${n.is_read ? "" : "bg-brand-50/50"}`}>
          <span className="text-xl">{ICON[n.type] || "🔔"}</span>
          <div className="flex-1"><div className="font-medium">{n.title}</div><div className="text-sm text-slate-600">{n.message}</div><div className="mt-1 text-xs text-slate-400">{fmtDate(n.created_at)}{n.link && <> · <Link className="text-brand-600 hover:underline" href={n.link}>View</Link></>}</div></div>
          {!n.is_read && <button className="btn-ghost !py-1 text-xs" onClick={async () => { await api.post(`/api/notifications/${n.id}/read`); load(); }}>Mark read</button>}
          <button className="btn-ghost !py-1 text-xs text-slate-400" onClick={async () => { await api.delete(`/api/notifications/${n.id}`); load(); }}>✕</button>
        </div>)}
        {!items.length && <Empty>You&apos;re all caught up.</Empty>}
      </div>
    </div>
  );
}
