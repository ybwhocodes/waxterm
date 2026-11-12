import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { SafeUser, Session, User, UserRole } from "./types";

export function getUsersFilePath(): string {
  return process.env.WAXTERM_USERS_PATH || join(homedir(), ".waxterm_users.json");
}

const activeSessions = new Map<string, Session>();
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 hari

export function loadUsers(): User[] {
  const filePath = getUsersFilePath();
  if (!existsSync(filePath)) {
    return [];
  }
  try {
    const raw = readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.filter((u) => u && u.id && u.username && u.passwordHash);
    }
    return [];
  } catch (err: any) {
    console.warn(`[!] Gagal membaca database pengguna di ${filePath}: ${err.message}`);
    return [];
  }
}

export function saveUsers(users: User[]): void {
  const filePath = getUsersFilePath();
  const content = JSON.stringify(users, null, 2);
  writeFileSync(filePath, content, { mode: 0o600 });
  try {
    chmodSync(filePath, 0o600);
  } catch {
    // Abaikan jika OS non-POSIX
  }
}

export function toSafeUser(user: User): SafeUser {
  const { passwordHash: _, ...safe } = user;
  return safe;
}

export async function hashPassword(password: string): Promise<string> {
  return await Bun.password.hash(password, {
    algorithm: "bcrypt",
    cost: 10,
  });
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await Bun.password.verify(password, hash);
  } catch {
    return false;
  }
}

export function validateUsername(username: string): { valid: boolean; error?: string } {
  if (!username || typeof username !== "string") {
    return { valid: false, error: "Username tidak boleh kosong." };
  }
  const trimmed = username.trim();
  if (trimmed.length < 3 || trimmed.length > 32) {
    return { valid: false, error: "Username harus memiliki panjang antara 3 hingga 32 karakter." };
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
    return { valid: false, error: "Username hanya boleh mengandung huruf, angka, underscore (_), atau dash (-)." };
  }
  return { valid: true };
}

export async function ensureDefaultSuperAdmin(): Promise<SafeUser> {
  const users = loadUsers();
  const existingSuperAdmin = users.find((u) => u.role === "super_admin");
  if (existingSuperAdmin) {
    return toSafeUser(existingSuperAdmin);
  }

  // Jika belum ada super_admin sama sekali, buat default 'admin'
  const defaultPassword = process.env.WAXTERM_DEFAULT_ADMIN_PASSWORD || "admin123";
  const passwordHash = await hashPassword(defaultPassword);
  const now = new Date().toISOString();

  const superAdmin: User = {
    id: `usr_${Date.now()}_root`,
    username: "admin",
    name: "Super Administrator",
    role: "super_admin",
    passwordHash,
    createdAt: now,
    updatedAt: now,
  };

  users.unshift(superAdmin);
  saveUsers(users);
  console.log("[*] Akun default Super Admin diinisialisasi (username: admin / password: admin123)");
  return toSafeUser(superAdmin);
}

export async function createUser(params: {
  username: string;
  name?: string;
  password: string;
  role: UserRole;
}): Promise<{ ok: boolean; user?: SafeUser; error?: string }> {
  const uv = validateUsername(params.username);
  if (!uv.valid) {
    return { ok: false, error: uv.error };
  }

  if (!params.password || params.password.length < 6) {
    return { ok: false, error: "Password minimal harus 6 karakter." };
  }

  if (params.role !== "super_admin" && params.role !== "admin") {
    return { ok: false, error: "Role pengguna harus 'super_admin' atau 'admin'." };
  }

  const users = loadUsers();
  const cleanUsername = params.username.trim().toLowerCase();

  if (users.some((u) => u.username.toLowerCase() === cleanUsername)) {
    return { ok: false, error: `Username '${cleanUsername}' sudah terdaftar.` };
  }

  const passwordHash = await hashPassword(params.password);
  const now = new Date().toISOString();

  const newUser: User = {
    id: `usr_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    username: cleanUsername,
    name: params.name?.trim() || cleanUsername,
    role: params.role,
    passwordHash,
    createdAt: now,
    updatedAt: now,
  };

  users.push(newUser);
  saveUsers(users);
  return { ok: true, user: toSafeUser(newUser) };
}

export async function updateUser(
  id: string,
  updates: {
    name?: string;
    role?: UserRole;
    password?: string;
  }
): Promise<{ ok: boolean; user?: SafeUser; error?: string }> {
  const users = loadUsers();
  const index = users.findIndex((u) => u.id === id);
  if (index === -1) {
    return { ok: false, error: "Pengguna tidak ditemukan." };
  }

  const user = users[index];

  // Cegah mengubah role jika dia adalah satu-satunya super_admin
  if (updates.role && updates.role !== "super_admin" && user.role === "super_admin") {
    const superAdminCount = users.filter((u) => u.role === "super_admin").length;
    if (superAdminCount <= 1) {
      return { ok: false, error: "Tidak dapat mengubah role satu-satunya Super Admin dalam sistem." };
    }
  }

  if (updates.name) {
    user.name = updates.name.trim();
  }

  if (updates.role) {
    if (updates.role !== "super_admin" && updates.role !== "admin") {
      return { ok: false, error: "Role tidak valid." };
    }
    user.role = updates.role;
  }

  if (updates.password) {
    if (updates.password.length < 6) {
      return { ok: false, error: "Password baru minimal harus 6 karakter." };
    }
    user.passwordHash = await hashPassword(updates.password);
  }

  user.updatedAt = new Date().toISOString();
  users[index] = user;
  saveUsers(users);

  return { ok: true, user: toSafeUser(user) };
}

export function deleteUser(id: string): { ok: boolean; error?: string } {
  const users = loadUsers();
  const target = users.find((u) => u.id === id);
  if (!target) {
    return { ok: false, error: "Pengguna tidak ditemukan." };
  }

  if (target.role === "super_admin") {
    const superAdminCount = users.filter((u) => u.role === "super_admin").length;
    if (superAdminCount <= 1) {
      return { ok: false, error: "Tidak dapat menghapus satu-satunya Super Admin dalam sistem." };
    }
  }

  const filtered = users.filter((u) => u.id !== id);
  saveUsers(filtered);

  // Bersihkan active sessions milik user ini
  for (const [token, session] of activeSessions.entries()) {
    if (session.userId === id) {
      activeSessions.delete(token);
    }
  }

  return { ok: true };
}

export async function authenticateUser(
  username: string,
  pass: string
): Promise<{ ok: boolean; user?: SafeUser; error?: string }> {
  if (!username || !pass) {
    return { ok: false, error: "Username dan password harus diisi." };
  }

  const users = loadUsers();
  const cleanUsername = username.trim().toLowerCase();
  const user = users.find((u) => u.username.toLowerCase() === cleanUsername);

  if (!user) {
    return { ok: false, error: "Username atau password salah." };
  }

  const matches = await verifyPassword(pass, user.passwordHash);
  if (!matches) {
    return { ok: false, error: "Username atau password salah." };
  }

  return { ok: true, user: toSafeUser(user) };
}

export function createSession(user: SafeUser): Session {
  const token = `wxt_${crypto.randomUUID().replace(/-/g, "")}`;
  const now = Date.now();
  const session: Session = {
    token,
    userId: user.id,
    username: user.username,
    name: user.name,
    role: user.role,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
  };

  activeSessions.set(token, session);
  return session;
}

export function getSession(token: string | null | undefined): Session | null {
  if (!token) return null;
  const session = activeSessions.get(token);
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    activeSessions.delete(token);
    return null;
  }

  return session;
}

export function revokeSession(token: string): boolean {
  return activeSessions.delete(token);
}

export function getUserFromRequest(req: Request): Session | null {
  // 1. Bearer token di header
  const authHeader = req.headers.get("authorization");
  if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
    const token = authHeader.slice(7).trim();
    const session = getSession(token);
    if (session) return session;
  }

  // 2. Cookie waxterm_token
  const cookieHeader = req.headers.get("cookie");
  if (cookieHeader) {
    const match = cookieHeader.match(/waxterm_token=([a-zA-Z0-9_-]+)/);
    if (match && match[1]) {
      const session = getSession(match[1]);
      if (session) return session;
    }
  }

  return null;
}
