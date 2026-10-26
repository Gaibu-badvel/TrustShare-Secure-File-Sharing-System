"use client";
import React, { useEffect, useState } from "react";

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: React.ReactNode; wide?: boolean }) {
  useEffect(() => { const h = (e: KeyboardEvent) => e.key === "Escape" && onClose(); window.addEventListener("keydown", h); return () => window.removeEventListener("keydown", h); }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`max-h-[90vh] w-full overflow-y-auto rounded-xl bg-white p-6 shadow-xl ${wide ? "max-w-3xl" : "max-w-lg"}`}>
        <div className="mb-4 flex items-center justify-between"><h3 className="text-lg font-semibold">{title}</h3>
          <button className="btn-ghost !px-2 !py-1" onClick={onClose} aria-label="Close">✕</button></div>
        {children}
      </div>
    </div>
  );
}

const sevColor: Record<string, string> = {
  low: "bg-slate-100 text-slate-700", info: "bg-slate-100 text-slate-700", medium: "bg-amber-100 text-amber-800", warning: "bg-amber-100 text-amber-800",
  high: "bg-red-100 text-red-700", critical: "bg-red-200 text-red-900", active: "bg-emerald-100 text-emerald-700", expired: "bg-slate-200 text-slate-600",
  revoked: "bg-red-100 text-red-700", exhausted: "bg-amber-100 text-amber-800", ok: "bg-emerald-100 text-emerald-700", admin: "bg-brand-100 text-brand-700",
};
export const Badge = ({ children, kind }: { children: React.ReactNode; kind?: string }) => (
  <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${sevColor[kind || String(children)] || "bg-slate-100 text-slate-700"}`}>{children}</span>
);

export const Spinner = () => <div className="mx-auto h-6 w-6 animate-spin rounded-full border-2 border-brand-500 border-t-transparent" />;
export const Empty = ({ children }: { children: React.ReactNode }) => <div className="py-10 text-center text-sm text-slate-400">{children}</div>;

export function Alert({ kind = "error", children }: { kind?: "error" | "success" | "info"; children: React.ReactNode }) {
  if (!children) return null;
  const c = { error: "bg-red-50 text-red-700 border-red-200", success: "bg-emerald-50 text-emerald-700 border-emerald-200", info: "bg-sky-50 text-sky-700 border-sky-200" }[kind];
  return <div role="alert" className={`mb-3 rounded-lg border px-3 py-2 text-sm ${c}`}>{children}</div>;
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className="mb-3 block"><span className="label">{label}</span>{children}</label>;
}

export function Bars({ data, x, ys, colors = ["#6366f1", "#10b981"], height = 120 }: { data: any[]; x: string; ys: string[]; colors?: string[]; height?: number }) {
  const max = Math.max(1, ...data.flatMap((d) => ys.map((y) => d[y] || 0)));
  const bw = 100 / Math.max(1, data.length);
  return (
    <svg viewBox={`0 0 100 ${height / 3}`} preserveAspectRatio="none" className="w-full" style={{ height }}>
      {data.map((d, i) => ys.map((y, j) => {
        const h = ((d[y] || 0) / max) * (height / 3 - 2); const w = (bw * 0.8) / ys.length;
        return <rect key={`${i}-${y}`} x={i * bw + bw * 0.1 + j * w} y={height / 3 - h} width={w} height={h} fill={colors[j % colors.length]} rx={0.3}>
          <title>{`${d[x]} — ${y}: ${d[y] || 0}`}</title></rect>;
      }))}
    </svg>
  );
}

export function Progress({ value }: { value: number }) {
  return <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200"><div className={`h-full ${value > 90 ? "bg-red-500" : "bg-brand-500"}`} style={{ width: `${Math.min(100, value)}%` }} /></div>;
}

export function useToast() {
  const [msg, setMsg] = useState<{ t: string; k: "success" | "error" } | null>(null);
  useEffect(() => { if (msg) { const id = setTimeout(() => setMsg(null), 3500); return () => clearTimeout(id); } }, [msg]);
  const el = msg ? <div className={`fixed bottom-5 right-5 z-[60] rounded-lg px-4 py-2 text-sm text-white shadow-lg ${msg.k === "error" ? "bg-red-600" : "bg-emerald-600"}`}>{msg.t}</div> : null;
  return { toast: (t: string, k: "success" | "error" = "success") => setMsg({ t, k }), el };
}
