import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  authenticateUser,
  createSession,
  createUser,
  deleteUser,
  ensureDefaultSuperAdmin,
  getSession,
  hashPassword,
  loadUsers,
  revokeSession,
  updateUser,
  validateUsername,
  verifyPassword,
} from "../src/users";

describe("User Management & Authentication Audit", () => {
  let testUsersPath: string;
  const originalUsersPath = process.env.WAXTERM_USERS_PATH;

  beforeEach(() => {
    testUsersPath = join(tmpdir(), `waxterm_users_test_${Date.now()}_${Math.random().toString(36).slice(2)}.json`);
    process.env.WAXTERM_USERS_PATH = testUsersPath;
  });

  afterEach(() => {
    if (existsSync(testUsersPath)) {
      rmSync(testUsersPath, { force: true });
    }
    if (originalUsersPath) {
      process.env.WAXTERM_USERS_PATH = originalUsersPath;
    } else {
      delete process.env.WAXTERM_USERS_PATH;
    }
  });

  // Positive: Password hashing & verification
  test("hashPassword dan verifyPassword bekerja secara aman menggunakan bcrypt", async () => {
    const rawPass = "rahasiaDevOps123!";
    const hash = await hashPassword(rawPass);
    expect(hash).toBeDefined();
    expect(hash.startsWith("$2")).toBe(true);

    const matches = await verifyPassword(rawPass, hash);
    expect(matches).toBe(true);

    const wrongMatches = await verifyPassword("salahPassword", hash);
    expect(wrongMatches).toBe(false);
  });

  // Positive: Default Super Admin initialization
  test("ensureDefaultSuperAdmin menginisialisasi super admin default jika sistem belum punya user", async () => {
    const admin = await ensureDefaultSuperAdmin();
    expect(admin.username).toBe("admin");
    expect(admin.role).toBe("super_admin");

    const users = loadUsers();
    expect(users.length).toBe(1);
    expect(users[0].role).toBe("super_admin");
  });

  // Positive: Create Admin User & Role Separation
  test("createUser berhasil membuat user dengan role 'admin' atau 'super_admin'", async () => {
    const resAdmin = await createUser({
      username: "operator_budi",
      name: "Budi Santoso",
      password: "password123",
      role: "admin",
    });
    expect(resAdmin.ok).toBe(true);
    expect(resAdmin.user?.username).toBe("operator_budi");
    expect(resAdmin.user?.role).toBe("admin");

    const resSuper = await createUser({
      username: "lead_devops",
      name: "Lead DevOps",
      password: "password123",
      role: "super_admin",
    });
    expect(resSuper.ok).toBe(true);
    expect(resSuper.user?.role).toBe("super_admin");
  });

  // Negative: Validation checks
  test("validateUsername dan createUser menolak username kosong, terlalu pendek, atau karakter liar", async () => {
    expect(validateUsername("").valid).toBe(false);
    expect(validateUsername("ab").valid).toBe(false);
    expect(validateUsername("user space").valid).toBe(false);
    expect(validateUsername("user@bad").valid).toBe(false);

    const resShortPass = await createUser({
      username: "validuser",
      password: "123", // < 6 chars
      role: "admin",
    });
    expect(resShortPass.ok).toBe(false);
    expect(resShortPass.error).toContain("minimal");
  });

  // Negative: Duplicate username prevention
  test("createUser menolak registrasi username yang sudah ada (duplikat)", async () => {
    await createUser({
      username: "developer1",
      password: "password123",
      role: "admin",
    });

    const resDup = await createUser({
      username: "developer1",
      password: "password456",
      role: "admin",
    });
    expect(resDup.ok).toBe(false);
    expect(resDup.error).toContain("sudah terdaftar");
  });

  // Positive & Negative: Authentication Flow
  test("authenticateUser berhasil dengan kredensial benar dan gagal jika salah", async () => {
    await createUser({
      username: "tester",
      password: "validPassword123",
      role: "admin",
    });

    const successAuth = await authenticateUser("tester", "validPassword123");
    expect(successAuth.ok).toBe(true);
    expect(successAuth.user?.username).toBe("tester");

    const failAuth = await authenticateUser("tester", "wrongPassword");
    expect(failAuth.ok).toBe(false);

    const nonExistent = await authenticateUser("unknown", "any");
    expect(nonExistent.ok).toBe(false);
  });

  // Session Token Lifecycle
  test("createSession, getSession, dan revokeSession mengelola token dengan benar", async () => {
    const { user } = await createUser({
      username: "session_user",
      password: "password123",
      role: "admin",
    });

    const session = createSession(user!);
    expect(session.token.startsWith("wxt_")).toBe(true);

    const retrieved = getSession(session.token);
    expect(retrieved?.userId).toBe(user!.id);
    expect(retrieved?.username).toBe("session_user");

    // Revoke
    revokeSession(session.token);
    expect(getSession(session.token)).toBeNull();
  });

  // Protection: Cannot delete or downgrade last super admin
  test("deleteUser dan updateUser melindungi satu-satunya super admin dari penghapusan atau downgrade", async () => {
    const admin = await ensureDefaultSuperAdmin();

    // Coba hapus satu-satunya super admin
    const delRes = deleteUser(admin.id);
    expect(delRes.ok).toBe(false);
    expect(delRes.error).toContain("satu-satunya Super Admin");

    // Coba downgrade satu-satunya super admin ke admin biasa
    const updateRes = await updateUser(admin.id, { role: "admin" });
    expect(updateRes.ok).toBe(false);
    expect(updateRes.error).toContain("satu-satunya Super Admin");
  });
});
