import { loadConfig } from "./config";
import { executeViaRust } from "./executor";
import { callLlm, createInitialSystemMessage, WAXTERM_TOOLS } from "./llm";
import { checkDangerousCommand, validateHost } from "./security";
import { createWaxtermServer } from "./server";
import type { LlmMessage } from "./types";

// ponytail: pakai Bun.spawn panggil binary Rust waxterm-core; ganti bun:ffi saat butuh zero-process-overhead.

export async function runApp(cliArgs: string[] = process.argv.slice(2)): Promise<void> {
  // Flag --ui / -u untuk menjalankan Web UI
  if (cliArgs.includes("--ui") || cliArgs.includes("-u")) {
    const { url } = createWaxtermServer({ openBrowser: true });
    console.log(`\n🚀 [Waxterm UI] Aktif di: ${url}`);
    console.log(`[*] Buka ${url} di browser untuk mengelola koneksi SSH & berinteraksi dengan AI.`);
    return;
  }

  let host = cliArgs[0];
  if (!host) {
    console.log("Waxterm AI SSH Client");
    console.log("Pilihan antarmuka:");
    console.log("  1. Web UI Dashboard (Rekomendasi)");
    console.log("  2. CLI Interactive Terminal\n");
    const mode = prompt("Pilih mode [1/2, default: 1]: ");

    if (mode === null) {
      console.log("\nProses dibatalkan.");
      return;
    }

    if (mode.trim() === "1" || mode.trim() === "" || mode.trim().toLowerCase() === "ui") {
      const { url } = createWaxtermServer({ openBrowser: true });
      console.log(`\n🚀 [Waxterm UI] Berhasil dibuka di browser: ${url}`);
      return;
    }

    const inputHost = prompt("Host target (user@ip atau hostname): ");
    if (inputHost === null) {
      console.log("\nProses dibatalkan.");
      return;
    }
    host = inputHost.trim();
  }

  const hostValidation = validateHost(host);
  if (!hostValidation.valid) {
    console.error(`[!] Error: ${hostValidation.error}`);
    console.error("Contoh penggunaan valid: bun start user@192.168.1.50");
    process.exit(1);
  }

  let cfg;
  try {
    cfg = loadConfig();
  } catch (err: any) {
    console.error(`[!] Gagal memuat konfigurasi: ${err.message}`);
    process.exit(1);
  }

  console.log("==================================================");
  console.log(`[*] Waxterm aktif. Terhubung host: ${host}`);
  console.log(`[*] Model: ${cfg.model} | Endpoint: ${cfg.api_url}`);
  console.log("[*] Ketik instruksi DevOps dalam bahasa manusia (contoh: 'cek load cpu dan disk')");
  console.log("[*] Ketik 'exit' atau 'quit' untuk keluar.");
  console.log("==================================================\n");

  const messages: LlmMessage[] = [createInitialSystemMessage(host)];

  while (true) {
    const input = prompt(`ai@${host}> `);

    // Tangani EOF / Ctrl+D dengan aman tanpa infinite loop
    if (input === null) {
      console.log("\n[Waxterm] Sesi diakhiri. Sampai jumpa!");
      break;
    }

    const trimmedInput = input.trim();
    if (!trimmedInput) continue;
    if (["exit", "quit", ":q"].includes(trimmedInput.toLowerCase())) {
      console.log("[Waxterm] Sesi diakhiri. Sampai jumpa!");
      break;
    }

    messages.push({ role: "user", content: trimmedInput });

    // Loop agen LLM
    let stepCount = 0;
    const MAX_STEPS = 15; // Mencegah looping rekursif tak berujung

    while (stepCount < MAX_STEPS) {
      stepCount++;
      let msg: any;
      try {
        msg = await callLlm(cfg, messages, WAXTERM_TOOLS);
      } catch (err: any) {
        console.error(`[!] Error LLM: ${err.message}`);
        break;
      }

      messages.push(msg);

      if (!msg.tool_calls || msg.tool_calls.length === 0) {
        if (msg.content) {
          console.log(`\nAI: ${msg.content}\n`);
        }
        break;
      }

      for (const tc of msg.tool_calls) {
        if (tc.function.name === "run_command") {
          let cmdToRun = "";
          try {
            const args = JSON.parse(tc.function.arguments);
            cmdToRun = typeof args.command === "string" ? args.command : "";
          } catch {
            messages.push({
              role: "tool",
              tool_call_id: tc.id,
              content: JSON.stringify({ error: "Argumen perintah tidak valid (bukan JSON format)." }),
            });
            continue;
          }

          if (!cmdToRun) {
            messages.push({
              role: "tool",
              tool_call_id: tc.id,
              content: JSON.stringify({ error: "Perintah kosong tidak dapat dijalankan." }),
            });
            continue;
          }

          // Gate Keamanan & Audit
          const dangerCheck = checkDangerousCommand(cmdToRun);
          let userConfirmed = false;

          if (dangerCheck.isDangerous) {
            console.log("\n⚠️  [PERINGATAN KEAMANAN TINGKAT TINGGI] ⚠️");
            console.log(`Alasan: ${dangerCheck.reason}`);
            console.log(`Perintah: \x1b[31;1m${cmdToRun}\x1b[0m`);
            const confirm = prompt("Ketik persis 'YA' atau 'YES' untuk melanjutkan eksekusi destruktif ini: ");
            if (confirm && ["ya", "yes"].includes(confirm.trim().toLowerCase())) {
              userConfirmed = true;
            } else {
              console.log("[🛡️ Keamanan] Perintah destruktif dibatalkan demi keamanan.");
            }
          } else {
            const confirm = (prompt(`[CONFIRM] Jalankan di \`${host}\`: \`${cmdToRun}\`? [Y/n] `) || "").trim().toLowerCase();
            if (["", "y", "yes"].includes(confirm)) {
              userConfirmed = true;
            } else {
              console.log("[i] Perintah dibatalkan oleh pengguna.");
            }
          }

          let toolResult: string;
          if (userConfirmed) {
            const out = await executeViaRust(host, cmdToRun);
            console.log(`[STDOUT]\n${out.stdout || "(kosong)"}`);
            if (out.stderr) {
              console.log(`[STDERR]\n${out.stderr}`);
            }
            toolResult = JSON.stringify(out);
          } else {
            toolResult = JSON.stringify({
              exit_code: -1,
              stdout: "",
              stderr: "Dibatalkan oleh pengguna.",
              cancelled: true,
            });
          }

          messages.push({
            role: "tool",
            tool_call_id: tc.id,
            content: toolResult,
          });
        }
      }
    }

    if (stepCount >= MAX_STEPS) {
      console.warn("\n[!] Batas maksimum langkah interaksi tercapai untuk instruksi ini.");
    }
  }
}

if (import.meta.main) {
  runApp().catch((err) => {
    console.error(`[Fatal] ${err.message}`);
    process.exit(1);
  });
}
