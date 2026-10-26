import axios, { AxiosError } from "axios";

export const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const ACCESS = "ts_access", REFRESH = "ts_refresh";

export const tokens = {
  get access() { return typeof window === "undefined" ? null : localStorage.getItem(ACCESS); },
  get refresh() { return typeof window === "undefined" ? null : localStorage.getItem(REFRESH); },
  set(a: string, r?: string) { localStorage.setItem(ACCESS, a); if (r) localStorage.setItem(REFRESH, r); },
  clear() { localStorage.removeItem(ACCESS); localStorage.removeItem(REFRESH); },
};

export const api = axios.create({ baseURL: API });

api.interceptors.request.use((cfg) => {
  const t = tokens.access;
  if (t) cfg.headers.Authorization = `Bearer ${t}`;
  return cfg;
});

let refreshing: Promise<string | null> | null = null;
async function doRefresh(): Promise<string | null> {
  const r = tokens.refresh;
  if (!r) return null;
  try {
    const { data } = await axios.post(`${API}/api/auth/refresh`, { refresh_token: r });
    tokens.set(data.access_token, data.refresh_token);
    return data.access_token;
  } catch { tokens.clear(); return null; }
}

api.interceptors.response.use((r) => r, async (err: AxiosError) => {
  const cfg: any = err.config;
  const isAuthCall = cfg?.url?.includes("/api/auth/login") || cfg?.url?.includes("/api/auth/refresh") || cfg?.url?.includes("/mfa/verify");
  if (err.response?.status === 401 && !cfg._retry && !isAuthCall && tokens.refresh) {
    cfg._retry = true;
    refreshing = refreshing || doRefresh().finally(() => (refreshing = null));
    const t = await refreshing;
    if (t) { cfg.headers.Authorization = `Bearer ${t}`; return api(cfg); }
    if (typeof window !== "undefined") window.location.href = "/login";
  }
  return Promise.reject(err);
});

export function errMsg(e: any): string {
  const d = e?.response?.data;
  if (typeof d === "string") return d;
  if (d?.detail) {
    if (typeof d.detail === "string") return d.detail;
    if (Array.isArray(d.detail)) return d.detail.map((x: any) => (x.msg || "").replace("Value error, ", "")).join("; ");
  }
  return e?.message || "Something went wrong";
}

/** Download a file via the authenticated API and trigger a browser save. */
export async function saveBlob(url: string, fallbackName = "download", headers: Record<string, string> = {}) {
  const res = await api.get(url, { responseType: "blob", headers });
  const cd = res.headers["content-disposition"] || "";
  const m = /filename\*=UTF-8''([^;]+)/.exec(cd);
  const name = m ? decodeURIComponent(m[1]) : fallbackName;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(res.data); a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

export const fmtBytes = (n: number) => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"]; const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), 4);
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
};
export const fmtDate = (s?: string | null) => (s ? new Date(s + (s.endsWith("Z") ? "" : "Z")).toLocaleString() : "—");
