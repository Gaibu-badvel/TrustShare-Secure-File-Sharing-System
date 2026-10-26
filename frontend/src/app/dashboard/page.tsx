"use client";
import { Suspense, useCallback, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge, Spinner } from "@/components/ui";
import FilesTab from "@/components/tabs/FilesTab";
import SharedTab from "@/components/tabs/SharedTab";
import ActivityTab from "@/components/tabs/ActivityTab";
import NotificationsTab from "@/components/tabs/NotificationsTab";
import AnalyticsTab from "@/components/tabs/AnalyticsTab";
import SecurityTab from "@/components/tabs/SecurityTab";
import SettingsTab from "@/components/tabs/SettingsTab";
import AdminTab from "@/components/tabs/AdminTab";

const TABS = [["files", "📁 Files"], ["shared", "🤝 Sharing"], ["activity", "📜 Activity"], ["notifications", "🔔 Notifications"], ["analytics", "📊 Analytics"], ["security", "🛡️ Security"], ["settings", "⚙️ Settings"]];

function Dashboard() {
  const { user, loading, logout } = useAuth(), r = useRouter(), sp = useSearchParams();
  const tab = sp.get("tab") || "files";
  const [unread, setUnread] = useState(0);
  const pollUnread = useCallback(() => { api.get("/api/notifications", { params: { unread_only: true, limit: 1 } }).then((x) => setUnread(x.data.unread)).catch(() => {}); }, []);
  useEffect(() => { if (!loading && !user) r.replace("/login"); }, [loading, user, r]);
  useEffect(() => { if (!user) return; pollUnread(); const id = setInterval(pollUnread, 30000); return () => clearInterval(id); }, [user, pollUnread]);
  if (loading || !user) return <div className="mt-40"><Spinner /></div>;
  const tabs = user.role === "admin" ? [...TABS, ["admin", "👑 Admin"]] : TABS;
  const go = (t: string) => r.push(`/dashboard?tab=${t}`);

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 flex-col border-r bg-white p-4 md:flex">
        <Link href="/" className="mb-6 text-xl font-bold text-brand-700">🔐 TrustShare</Link>
        <nav className="flex-1 space-y-1">{tabs.map(([k, l]) => <button key={k} onClick={() => go(k)} className={`flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-sm font-medium ${tab === k ? "bg-brand-50 text-brand-700" : "text-slate-600 hover:bg-slate-100"}`}>
          {l}{k === "notifications" && unread > 0 && <span className="rounded-full bg-red-500 px-1.5 text-xs text-white">{unread}</span>}</button>)}</nav>
        <div className="border-t pt-3 text-sm"><div className="truncate font-medium">{user.full_name || user.username}</div><div className="truncate text-xs text-slate-500">{user.email}</div>
          <div className="mt-1 flex gap-1">{user.role === "admin" && <Badge kind="admin">admin</Badge>}{user.role === "viewer" && <Badge>viewer</Badge>}{user.mfa_enabled && <Badge kind="ok">MFA</Badge>}</div>
          <button className="btn-secondary mt-3 w-full" onClick={logout}>Sign out</button></div>
      </aside>
      <div className="flex-1 overflow-x-hidden">
        <div className="flex gap-1 overflow-x-auto border-b bg-white p-2 md:hidden">{tabs.map(([k, l]) => <button key={k} onClick={() => go(k)} className={`whitespace-nowrap rounded-lg px-3 py-1.5 text-sm ${tab === k ? "bg-brand-50 text-brand-700" : "text-slate-600"}`}>{l}</button>)}<button className="btn-ghost ml-auto whitespace-nowrap" onClick={logout}>Sign out</button></div>
        <main className="mx-auto max-w-6xl p-4 md:p-8">
          {!user.mfa_enabled && tab === "files" && <div className="mb-4 flex items-center justify-between rounded-lg border border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-800">Protect your account with multi-factor authentication.<button className="font-medium underline" onClick={() => go("settings")}>Enable MFA</button></div>}
          {tab === "files" && <FilesTab readOnly={user.role === "viewer"} />}
          {tab === "shared" && <SharedTab />}
          {tab === "activity" && <ActivityTab />}
          {tab === "notifications" && <NotificationsTab onChange={pollUnread} />}
          {tab === "analytics" && <AnalyticsTab />}
          {tab === "security" && <SecurityTab />}
          {tab === "settings" && <SettingsTab />}
          {tab === "admin" && user.role === "admin" && <AdminTab />}
        </main>
      </div>
    </div>
  );
}
export default function Page() { return <Suspense fallback={<div className="mt-40"><Spinner /></div>}><Dashboard /></Suspense>; }
