"use client";
import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api, tokens } from "./api";

type Ctx = { user: any; loading: boolean; refreshUser: () => Promise<void>; setSession: (d: any) => void; logout: () => Promise<void> };
const AuthCtx = createContext<Ctx>(null as any);
export const useAuth = () => useContext(AuthCtx);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const refreshUser = useCallback(async () => {
    if (!tokens.access && !tokens.refresh) { setUser(null); setLoading(false); return; }
    try { setUser((await api.get("/api/auth/me")).data); } catch { setUser(null); tokens.clear(); }
    setLoading(false);
  }, []);
  useEffect(() => { refreshUser(); }, [refreshUser]);

  const setSession = (d: any) => { tokens.set(d.access_token, d.refresh_token); if (d.user) setUser(d.user); };
  const logout = async () => {
    try { await api.post("/api/auth/logout"); } catch {}
    tokens.clear(); setUser(null); window.location.href = "/login";
  };
  return <AuthCtx.Provider value={{ user, loading, refreshUser, setSession, logout }}>{children}</AuthCtx.Provider>;
}
