import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { validateHost } from "./security";
import type { SshConnectionProfile } from "./types";

export function getConnectionsFilePath(): string {
  return process.env.WAXTERM_CONNECTIONS_PATH || join(homedir(), ".waxterm_connections.json");
}

export function loadConnections(userId?: string): SshConnectionProfile[] {
  const filePath = getConnectionsFilePath();
  if (!existsSync(filePath)) {
    return [];
  }
  try {
    const raw = readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      const valid = parsed.filter((item) => item && typeof item.host === "string" && item.id);
      if (userId) {
        return valid.filter((item) => !item.createdBy || item.createdBy === userId);
      }
      return valid;
    }
    return [];
  } catch (err: any) {
    console.warn(`[!] Gagal membaca file koneksi di ${filePath}: ${err.message}`);
    return [];
  }
}

export function getConnectionById(id: string): SshConnectionProfile | null {
  const all = loadConnections();
  return all.find((c) => c.id === id) || null;
}

export function saveConnections(connections: SshConnectionProfile[]): void {
  const filePath = getConnectionsFilePath();
  const content = JSON.stringify(connections, null, 2);
  writeFileSync(filePath, content, { mode: 0o600 });
  try {
    chmodSync(filePath, 0o600);
  } catch {
    // Abaikan di sistem tanpa izin POSIX
  }
}

export function addOrUpdateConnection(
  profile: Partial<SshConnectionProfile> & { host: string; id?: string },
  createdBy?: string
): { ok: boolean; connection?: SshConnectionProfile; error?: string } {
  const hostValidation = validateHost(profile.host);
  if (!hostValidation.valid) {
    return { ok: false, error: hostValidation.error };
  }

  // Validasi SSH username jika diisi
  if (profile.user && (profile.user.startsWith("-") || /[\s\0\r\n]/.test(profile.user))) {
    return { ok: false, error: "Username SSH tidak valid." };
  }

  // Validasi key path jika diisi
  if (profile.keyPath) {
    const trimmedKey = profile.keyPath.trim();
    if (trimmedKey.startsWith("-") || trimmedKey.contains?.("\0")) {
      return { ok: false, error: "Path SSH Key tidak valid (tidak boleh diawali '-')." };
    }
  }

  const port = profile.port && profile.port > 0 && profile.port <= 65535 ? Number(profile.port) : 22;
  const connections = loadConnections();
  const id = profile.id || `conn_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  const existingIndex = connections.findIndex((c) => c.id === id);

  const now = new Date().toISOString();

  const newConn: SshConnectionProfile = {
    id,
    name: profile.name?.trim() || `${profile.user ? profile.user + "@" : ""}${profile.host}`,
    host: profile.host.trim(),
    user: profile.user?.trim() || undefined,
    port,
    authType: profile.authType === "password" || profile.authType === "agent" ? profile.authType : "key",
    keyPath: profile.keyPath?.trim() || undefined,
    password: profile.password?.trim() || undefined,
    notes: profile.notes?.trim() || undefined,
    createdBy: profile.createdBy || createdBy,
    createdAt: existingIndex >= 0 ? connections[existingIndex].createdAt || now : now,
    lastConnectedAt: profile.lastConnectedAt || (existingIndex >= 0 ? connections[existingIndex].lastConnectedAt : undefined),
  };

  if (existingIndex >= 0) {
    connections[existingIndex] = newConn;
  } else {
    connections.unshift(newConn);
  }

  saveConnections(connections);
  return { ok: true, connection: newConn };
}

export function recordConnectionUsed(id: string): void {
  const connections = loadConnections();
  const index = connections.findIndex((c) => c.id === id);
  if (index >= 0) {
    connections[index].lastConnectedAt = new Date().toISOString();
    saveConnections(connections);
  }
}

export function deleteConnection(id: string): boolean {
  const connections = loadConnections();
  const filtered = connections.filter((c) => c.id !== id);
  if (filtered.length !== connections.length) {
    saveConnections(filtered);
    return true;
  }
  return false;
}
