import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getExistingConfig, saveConfig, validateConfig } from "./config";
import {
  addOrUpdateConnection,
  deleteConnection,
  getConnectionById,
  loadConnections,
  recordConnectionUsed,
} from "./connections";
import { executeViaRust } from "./executor";
import { callLlm, createInitialSystemMessage, WAXTERM_TOOLS } from "./llm";
import { checkDangerousCommand, validateHost } from "./security";
import type { Config, LlmMessage } from "./types";
import {
  authenticateUser,
  createSession,
  createUser,
  deleteUser,
  ensureDefaultSuperAdmin,
  getUserFromRequest,
  loadUsers,
  revokeSession,
  toSafeUser,
  updateUser,
} from "./users";

export interface ServerOptions {
  port?: number;
  openBrowser?: boolean;
}

const UI_HTML_PATH = join(import.meta.dir, "ui", "index.html");

export function maskApiKey(key: string): string {
  if (!key) return "";
  if (key.length <= 8) return "********";
  return key.slice(0, 4) + "..." + key.slice(-4);
}

export function createWaxtermServer(options: ServerOptions = {}) {
  const port = options.port !== undefined ? options.port : parseInt(process.env.PORT || "3888");

  // Inisialisasi default super admin jika belum ada
  ensureDefaultSuperAdmin().catch((err) => {
    console.warn(`[!] Inisialisasi default super admin error: ${err.message}`);
  });

  const server = Bun.serve({
    port,
    async fetch(req) {
      const url = new URL(req.url);

      // CORS Preflight
      if (req.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
          },
        });
      }

      // Helper JSON Response dengan CORS
      const jsonResponse = (data: any, status: number = 200, headers: Record<string, string> = {}) => {
        return Response.json(data, {
          status,
          headers: {
            "Access-Control-Allow-Origin": "*",
            ...headers,
          },
        });
      };

      // 1. Serve Frontend UI
      if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        const html = readFileSync(UI_HTML_PATH, "utf-8");
        return new Response(html, {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      // ---------------- AUTHENTICATION APIS ----------------
      // POST /api/auth/login
      if (req.method === "POST" && url.pathname === "/api/auth/login") {
        try {
          const body = await req.json();
          const { username, password } = body || {};
          const authResult = await authenticateUser(username, password);
          if (!authResult.ok || !authResult.user) {
            return jsonResponse({ ok: false, error: authResult.error || "Login gagal." }, 401);
          }

          const session = createSession(authResult.user);
          return jsonResponse(
            {
              ok: true,
              token: session.token,
              user: authResult.user,
            },
            200,
            {
              "Set-Cookie": `waxterm_token=${session.token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`,
            }
          );
        } catch (err: any) {
          return jsonResponse({ ok: false, error: err.message }, 500);
        }
      }

      // POST /api/auth/logout
      if (req.method === "POST" && url.pathname === "/api/auth/logout") {
        const session = getUserFromRequest(req);
        if (session) {
          revokeSession(session.token);
        }
        return jsonResponse(
          { ok: true },
          200,
          {
            "Set-Cookie": "waxterm_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
          }
        );
      }

      // GET /api/auth/me
      if (req.method === "GET" && url.pathname === "/api/auth/me") {
        const session = getUserFromRequest(req);
        if (!session) {
          return jsonResponse({ ok: false, error: "Belum login." }, 401);
        }
        return jsonResponse({
          ok: true,
          user: {
            id: session.userId,
            username: session.username,
            name: session.name,
            role: session.role,
          },
        });
      }

      // Auth Guard untuk semua API /api/* selanjutnya
      const currentSession = getUserFromRequest(req);
      if (url.pathname.startsWith("/api/")) {
        if (!currentSession) {
          return jsonResponse({ ok: false, error: "Akses ditolak: silakan login terlebih dahulu." }, 401);
        }
      }

      // ---------------- USER MANAGEMENT (SUPER ADMIN ONLY) ----------------
      // GET /api/users
      if (req.method === "GET" && url.pathname === "/api/users") {
        if (currentSession?.role !== "super_admin") {
          return jsonResponse({ ok: false, error: "Hanya Super Admin yang diizinkan mengelola pengguna." }, 403);
        }
        const users = loadUsers().map(toSafeUser);
        return jsonResponse({ ok: true, users });
      }

      // POST /api/users (Buat user baru)
      if (req.method === "POST" && url.pathname === "/api/users") {
        if (currentSession?.role !== "super_admin") {
          return jsonResponse({ ok: false, error: "Hanya Super Admin yang diizinkan menambah pengguna." }, 403);
        }
        try {
          const body = await req.json();
          const result = await createUser(body);
          if (!result.ok) {
            return jsonResponse({ ok: false, error: result.error }, 400);
          }
          return jsonResponse({ ok: true, user: result.user }, 201);
        } catch (err: any) {
          return jsonResponse({ ok: false, error: err.message }, 500);
        }
      }

      // PUT /api/users/:id (Update user / reset password / role)
      if (req.method === "PUT" && url.pathname.startsWith("/api/users/")) {
        if (currentSession?.role !== "super_admin") {
          return jsonResponse({ ok: false, error: "Hanya Super Admin yang diizinkan mengubah pengguna." }, 403);
        }
        try {
          const id = url.pathname.replace("/api/users/", "");
          const body = await req.json();
          const result = await updateUser(id, body);
          if (!result.ok) {
            return jsonResponse({ ok: false, error: result.error }, 400);
          }
          return jsonResponse({ ok: true, user: result.user });
        } catch (err: any) {
          return jsonResponse({ ok: false, error: err.message }, 500);
        }
      }

      // DELETE /api/users/:id (Hapus user)
      if (req.method === "DELETE" && url.pathname.startsWith("/api/users/")) {
        if (currentSession?.role !== "super_admin") {
          return jsonResponse({ ok: false, error: "Hanya Super Admin yang diizinkan menghapus pengguna." }, 403);
        }
        const id = url.pathname.replace("/api/users/", "");
        if (id === currentSession.userId) {
          return jsonResponse({ ok: false, error: "Anda tidak dapat menghapus akun Anda sendiri saat sedang login." }, 400);
        }
        const result = deleteUser(id);
        if (!result.ok) {
          return jsonResponse({ ok: false, error: result.error }, 400);
        }
        return jsonResponse({ ok: true });
      }

      // ---------------- AI CONFIG APIS ----------------
      // GET /api/config
      if (req.method === "GET" && url.pathname === "/api/config") {
        const cfg = getExistingConfig();
        if (cfg) {
          return jsonResponse({
            api_url: cfg.api_url,
            api_key: cfg.api_key,
            model: cfg.model,
          });
        }
        return jsonResponse({ api_url: "", api_key: "", model: "gpt-4o" });
      }

      // POST /api/config
      if (req.method === "POST" && url.pathname === "/api/config") {
        try {
          const body = (await req.json()) as Config;
          const validation = validateConfig(body);
          if (!validation.valid) {
            return jsonResponse({ ok: false, error: validation.error }, 400);
          }
          saveConfig({
            api_url: body.api_url.trim().replace(/\/+$/, ""),
            api_key: body.api_key.trim(),
            model: body.model.trim(),
          });
          return jsonResponse({ ok: true });
        } catch (err: any) {
          return jsonResponse({ ok: false, error: err.message }, 500);
        }
      }

      // ---------------- SAVED SSH CONNECTIONS APIS ----------------
      // GET /api/connections
      if (req.method === "GET" && url.pathname === "/api/connections") {
        const connections = loadConnections();
        return jsonResponse(connections);
      }

      // POST /api/connections
      if (req.method === "POST" && url.pathname === "/api/connections") {
        try {
          const body = await req.json();
          const result = addOrUpdateConnection(body, currentSession?.userId);
          if (!result.ok) {
            return jsonResponse({ ok: false, error: result.error }, 400);
          }
          return jsonResponse({ ok: true, connection: result.connection });
        } catch (err: any) {
          return jsonResponse({ ok: false, error: err.message }, 500);
        }
      }

      // DELETE /api/connections/:id
      if (req.method === "DELETE" && url.pathname.startsWith("/api/connections/")) {
        const id = url.pathname.replace("/api/connections/", "");
        const deleted = deleteConnection(id);
        return jsonResponse({ ok: deleted });
      }

      // POST /api/connections/:id/connect (1-CLICK DIRECT CONNECT)
      if (req.method === "POST" && url.pathname.match(/^\/api\/connections\/[^/]+\/connect$/)) {
        const id = url.pathname.split("/")[3];
        const profile = getConnectionById(id);
        if (!profile) {
          return jsonResponse({ ok: false, error: "Profil koneksi tidak ditemukan." }, 404);
        }

        const target = profile.user ? `${profile.user}@${profile.host}` : profile.host;
        const hostValidation = validateHost(profile.host);
        if (!hostValidation.valid) {
          return jsonResponse({ ok: false, error: hostValidation.error }, 400);
        }

        recordConnectionUsed(id);

        // Eksekusi probe inspeksi sistem remote secara instan
        const probeResult = await executeViaRust(target, "uname -srm 2>/dev/null || uname -a; uptime 2>/dev/null", {
          port: profile.port,
          keyPath: profile.keyPath,
          password: profile.password,
          timeoutMs: 10000,
        });

        return jsonResponse({
          ok: true,
          profile,
          target,
          probe: probeResult,
        });
      }

      // ---------------- SSH EXECUTION & AI APIS ----------------
      // POST /api/test-connection
      if (req.method === "POST" && url.pathname === "/api/test-connection") {
        try {
          const { host, port: sshPort, keyPath, password } = await req.json();
          const hostValidation = validateHost(host);
          if (!hostValidation.valid) {
            return jsonResponse({ ok: false, error: hostValidation.error }, 400);
          }
          const start = Date.now();
          const result = await executeViaRust(host, "echo 'waxterm_conn_probe'", {
            port: sshPort,
            keyPath,
            password,
            timeoutMs: 8000,
          });
          const latencyMs = Date.now() - start;
          if (result.exit_code === 0) {
            return jsonResponse({ ok: true, latencyMs });
          } else {
            return jsonResponse({ ok: false, error: result.stderr || "Koneksi SSH gagal." }, 502);
          }
        } catch (err: any) {
          return jsonResponse({ ok: false, error: err.message }, 500);
        }
      }

      // POST /api/execute (Direct shell command)
      if (req.method === "POST" && url.pathname === "/api/execute") {
        try {
          const { host, command, port: sshPort, keyPath, password } = await req.json();
          const hostValidation = validateHost(host);
          if (!hostValidation.valid) {
            return jsonResponse({ ok: false, error: hostValidation.error }, 400);
          }
          const out = await executeViaRust(host, command, {
            port: sshPort,
            keyPath,
            password,
          });
          return jsonResponse(out);
        } catch (err: any) {
          return jsonResponse({ exit_code: -1, stdout: "", stderr: err.message }, 500);
        }
      }

      // POST /api/ai/chat
      if (req.method === "POST" && url.pathname === "/api/ai/chat") {
        try {
          const { host, messages: clientMessages } = await req.json();
          const hostValidation = validateHost(host);
          if (!hostValidation.valid) {
            return jsonResponse({ ok: false, error: hostValidation.error }, 400);
          }

          const cfg = getExistingConfig();
          if (!cfg) {
            return jsonResponse(
              { ok: false, error: "Konfigurasi AI belum diatur. Silakan atur di tab Pengaturan AI." },
              400
            );
          }

          const fullMessages: LlmMessage[] = [
            createInitialSystemMessage(host),
            ...(Array.isArray(clientMessages) ? clientMessages : []),
          ];

          const msg = await callLlm(cfg, fullMessages, WAXTERM_TOOLS);

          if (msg.tool_calls && msg.tool_calls.length > 0) {
            const tc = msg.tool_calls[0];
            let command = "";
            try {
              const args = JSON.parse(tc.function.arguments);
              command = args.command || "";
            } catch {
              command = tc.function.arguments;
            }

            const danger = checkDangerousCommand(command);

            return jsonResponse({
              status: "requires_confirmation",
              command,
              tool_call: {
                id: tc.id,
                command,
              },
              danger,
            });
          }

          return jsonResponse({
            status: "completed",
            reply: msg.content,
          });
        } catch (err: any) {
          return jsonResponse({ ok: false, error: err.message }, 500);
        }
      }

      // POST /api/ai/confirm
      if (req.method === "POST" && url.pathname === "/api/ai/confirm") {
        try {
          const { host, approved, tool_call, messages: clientMessages, port: sshPort, keyPath, password } = await req.json();
          let toolResult: any;

          if (approved) {
            toolResult = await executeViaRust(host, tool_call.command, {
              port: sshPort,
              keyPath,
              password,
            });
          } else {
            toolResult = {
              exit_code: -1,
              stdout: "",
              stderr: "Perintah dibatalkan oleh pengguna.",
              cancelled: true,
            };
          }

          const cfg = getExistingConfig();
          if (!cfg) {
            return jsonResponse({
              ...toolResult,
              next_reply: approved ? "Perintah telah dijalankan." : "Perintah telah dibatalkan.",
            });
          }

          const fullMessages: LlmMessage[] = [
            createInitialSystemMessage(host),
            ...(Array.isArray(clientMessages) ? clientMessages : []),
            {
              role: "assistant",
              tool_calls: [
                {
                  id: tool_call.id,
                  type: "function",
                  function: {
                    name: "run_command",
                    arguments: JSON.stringify({ command: tool_call.command }),
                  },
                },
              ],
            },
            {
              role: "tool",
              tool_call_id: tool_call.id,
              content: JSON.stringify(toolResult),
            },
          ];

          let nextReply = "";
          try {
            const nextMsg = await callLlm(cfg, fullMessages, []);
            nextReply = nextMsg.content || "";
          } catch {
            nextReply = approved ? "Perintah selesai dijalankan." : "Perintah dibatalkan.";
          }

          return jsonResponse({
            ...toolResult,
            next_reply: nextReply,
          });
        } catch (err: any) {
          return jsonResponse({ ok: false, error: err.message }, 500);
        }
      }

      return new Response("Not Found", { status: 404 });
    },
  });

  const url = `http://localhost:${server.port}`;

  if (options.openBrowser) {
    try {
      Bun.spawn(["open", url]);
    } catch {
      // Abaikan jika tidak di lingkungan desktop
    }
  }

  return { server, url };
}

if (import.meta.main) {
  const { url } = createWaxtermServer({ openBrowser: true });
  console.log(`\n🚀 [Waxterm UI] Aktif di: ${url}`);
  console.log(`[*] Login default: username 'admin', password 'admin123'`);
  console.log(`[*] Buka ${url} di browser untuk menghubungkan SSH & berinteraksi dengan AI.`);
}
