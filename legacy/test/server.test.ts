import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createWaxtermServer, maskApiKey } from "../src/server";
import { createUser, ensureDefaultSuperAdmin } from "../src/users";

describe("UI Server & API Audit", () => {
  let serverInstance: any;
  let baseUrl: string;
  let testConfigPath: string;
  let testConnPath: string;
  let testUsersPath: string;
  let mockSshScriptPath: string;
  let superAdminToken: string;
  let adminToken: string;

  beforeAll(async () => {
    testConfigPath = join(tmpdir(), `waxterm_server_cfg_${Date.now()}.json`);
    testConnPath = join(tmpdir(), `waxterm_server_conn_${Date.now()}.json`);
    testUsersPath = join(tmpdir(), `waxterm_server_users_${Date.now()}.json`);

    process.env.WAXTERM_CONFIG_PATH = testConfigPath;
    process.env.WAXTERM_CONNECTIONS_PATH = testConnPath;
    process.env.WAXTERM_USERS_PATH = testUsersPath;

    // Siapkan mock SSH binary
    mockSshScriptPath = join(tmpdir(), `mock_ssh_server_${Date.now()}.sh`);
    const scriptContent = `#!/bin/bash
cmd=""
for arg in "$@"; do
  cmd="$arg"
done
if [[ "$cmd" == *"uname"* ]]; then
  echo "Linux waxterm-node 5.15.0-generic x86_64; up 14 days"
  exit 0
elif [ "$cmd" = "echo 'waxterm_conn_probe'" ]; then
  echo "waxterm_conn_probe"
  exit 0
else
  echo "stdout: $cmd"
  exit 0
fi
`;
    writeFileSync(mockSshScriptPath, scriptContent, { mode: 0o755 });
    chmodSync(mockSshScriptPath, 0o755);
    process.env.WAXTERM_SSH_BIN = mockSshScriptPath;

    // Tulis config awal untuk tes
    Bun.write(
      testConfigPath,
      JSON.stringify({
        api_url: "https://api.openai.com/v1",
        api_key: "sk-test-secret-key-12345",
        model: "gpt-4o",
      })
    );

    // Jalankan server di port 0 (port dinamis bebas)
    const { server, url } = createWaxtermServer({ port: 0, openBrowser: false });
    serverInstance = server;
    baseUrl = url;

    // Inisialisasi default super admin & user biasa
    await ensureDefaultSuperAdmin();
    await createUser({
      username: "regular_admin",
      name: "Regular Admin",
      password: "password123",
      role: "admin",
    });

    // Login sebagai super admin
    const loginSuper = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "admin123" }),
    });
    const superData = await loginSuper.json();
    superAdminToken = superData.token;

    // Login sebagai regular admin
    const loginRegular = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "regular_admin", password: "password123" }),
    });
    const regularData = await loginRegular.json();
    adminToken = regularData.token;
  });

  afterAll(() => {
    if (serverInstance) {
      serverInstance.stop();
    }
    if (existsSync(testConfigPath)) rmSync(testConfigPath, { force: true });
    if (existsSync(testConnPath)) rmSync(testConnPath, { force: true });
    if (existsSync(testUsersPath)) rmSync(testUsersPath, { force: true });
    if (existsSync(mockSshScriptPath)) rmSync(mockSshScriptPath, { force: true });
  });

  test("maskApiKey menyamarkan kunci sensitif untuk tampilan UI", () => {
    expect(maskApiKey("sk-1234567890abcdef")).toBe("sk-1...cdef");
    expect(maskApiKey("short")).toBe("********");
    expect(maskApiKey("")).toBe("");
  });

  // Positive: Frontend UI HTML
  test("GET / menyajikan UI Dashboard HTML lengkap (status 200)", async () => {
    const res = await fetch(`${baseUrl}/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Waxterm");
    expect(html).toContain("Koneksi SSH");
    expect(html).toContain("Manajemen Pengguna");
    expect(html).toContain("<!DOCTYPE html>");
  });

  // Negative: Protected API without token
  test("Endpoint /api/* menolak akses tanpa token autentikasi (HTTP 401)", async () => {
    const res = await fetch(`${baseUrl}/api/connections`);
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.ok).toBe(false);
  });

  // Positive: Auth session
  test("GET /api/auth/me mengembalikan profil sesi pengguna yang sedang login", async () => {
    const res = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Authorization: `Bearer ${superAdminToken}` },
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.ok).toBe(true);
    expect(data.user.username).toBe("admin");
    expect(data.user.role).toBe("super_admin");
  });

  // RBAC: User Management (Super Admin vs Admin)
  test("GET /api/users hanya dapat diakses oleh Super Admin (Admin biasa ditolak HTTP 403)", async () => {
    // Akses via Super Admin: Harus Sukses
    const resSuper = await fetch(`${baseUrl}/api/users`, {
      headers: { Authorization: `Bearer ${superAdminToken}` },
    });
    expect(resSuper.status).toBe(200);
    const dataSuper = await resSuper.json();
    expect(dataSuper.ok).toBe(true);
    expect(Array.isArray(dataSuper.users)).toBe(true);

    // Akses via Admin Biasa: Harus Ditolak 403
    const resAdmin = await fetch(`${baseUrl}/api/users`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    expect(resAdmin.status).toBe(403);
    const dataAdmin = await resAdmin.json();
    expect(dataAdmin.ok).toBe(false);
  });

  test("Super Admin dapat membuat, memperbarui, dan menghapus user admin via API", async () => {
    // 1. Create user baru
    const createRes = await fetch(`${baseUrl}/api/users`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${superAdminToken}`,
      },
      body: JSON.stringify({
        username: "devops_newbie",
        name: "Newbie DevOps",
        password: "newbiePassword123",
        role: "admin",
      }),
    });
    expect(createRes.status).toBe(201);
    const createData = await createRes.json();
    expect(createData.ok).toBe(true);
    const newUserId = createData.user.id;

    // 2. Update user
    const updateRes = await fetch(`${baseUrl}/api/users/${newUserId}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${superAdminToken}`,
      },
      body: JSON.stringify({ name: "Senior DevOps" }),
    });
    expect(updateRes.status).toBe(200);
    const updateData = await updateRes.json();
    expect(updateData.user.name).toBe("Senior DevOps");

    // 3. Delete user
    const deleteRes = await fetch(`${baseUrl}/api/users/${newUserId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${superAdminToken}` },
    });
    expect(deleteRes.status).toBe(200);
    const delData = await deleteRes.json();
    expect(delData.ok).toBe(true);
  });

  // Saved SSH Connections & 1-Click Direct Connect API
  test("POST & GET /api/connections menyimpan server SSH", async () => {
    const addRes = await fetch(`${baseUrl}/api/connections`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        name: "Singapore Web VPS",
        host: "192.168.1.50",
        port: 22,
        user: "ubuntu",
        authType: "key",
        keyPath: "~/.ssh/id_rsa",
      }),
    });
    expect(addRes.status).toBe(200);
    const addData = await addRes.json();
    expect(addData.ok).toBe(true);
    expect(addData.connection.name).toBe("Singapore Web VPS");

    const listRes = await fetch(`${baseUrl}/api/connections`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    const list = await listRes.json();
    expect(list.some((c: any) => c.name === "Singapore Web VPS")).toBe(true);
  });

  test("POST /api/connections/:id/connect melakukan 1-Click Connect dan mengembalikan hasil probe", async () => {
    // Tambah satu profil server dulu
    const addRes = await fetch(`${baseUrl}/api/connections`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        name: "Quick Connect Test VPS",
        host: "vps.node.internal",
        user: "root",
      }),
    });
    const { connection } = await addRes.json();

    // Panggil 1-Click Direct Connect endpoint
    const connectRes = await fetch(`${baseUrl}/api/connections/${connection.id}/connect`, {
      method: "POST",
      headers: { Authorization: `Bearer ${adminToken}` },
    });

    expect(connectRes.status).toBe(200);
    const connectData = await connectRes.json();
    expect(connectData.ok).toBe(true);
    expect(connectData.target).toBe("root@vps.node.internal");
    expect(connectData.probe.exit_code).toBe(0);
    expect(connectData.probe.stdout).toContain("Linux waxterm-node");
  });

  // Config API
  test("GET & POST /api/config bekerja dengan autentikasi", async () => {
    const postRes = await fetch(`${baseUrl}/api/config`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        api_url: "http://localhost:11434/v1",
        api_key: "ollama-key",
        model: "deepseek-coder",
      }),
    });
    expect(postRes.status).toBe(200);

    const getRes = await fetch(`${baseUrl}/api/config`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    const data = await getRes.json();
    expect(data.model).toBe("deepseek-coder");
  });
});
