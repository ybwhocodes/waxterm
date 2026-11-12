import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Config } from "./types";

export function getConfigPath(): string {
  return process.env.WAXTERM_CONFIG_PATH || join(homedir(), ".ai_ssh_config.json");
}

export function validateConfig(cfg: any): { valid: boolean; error?: string } {
  if (!cfg || typeof cfg !== "object") {
    return { valid: false, error: "Konfigurasi harus berupa object JSON valid." };
  }
  if (!cfg.api_url || typeof cfg.api_url !== "string" || cfg.api_url.trim() === "") {
    return { valid: false, error: "api_url tidak boleh kosong." };
  }
  if (!cfg.api_key || typeof cfg.api_key !== "string" || cfg.api_key.trim() === "") {
    return { valid: false, error: "api_key tidak boleh kosong." };
  }
  if (!cfg.model || typeof cfg.model !== "string" || cfg.model.trim() === "") {
    return { valid: false, error: "model tidak boleh kosong." };
  }
  return { valid: true };
}

export function saveConfig(cfg: Config, targetPath: string = getConfigPath()): void {
  const content = JSON.stringify(cfg, null, 2);
  writeFileSync(targetPath, content, { mode: 0o600 });
  try {
    chmodSync(targetPath, 0o600);
  } catch {
    // Di lingkungan non-POSIX chmod mungkin diabaikan
  }
}

export function getExistingConfig(): Config | null {
  // 1. Prioritaskan environment variables jika tersedia
  const envUrl = process.env.AI_API_URL;
  const envKey = process.env.AI_API_KEY;
  const envModel = process.env.AI_MODEL;

  if (envUrl && envKey) {
    const config: Config = {
      api_url: envUrl.trim().replace(/\/+$/, ""),
      api_key: envKey.trim(),
      model: (envModel || "gpt-4o").trim(),
    };
    const validation = validateConfig(config);
    if (validation.valid) {
      return config;
    }
  }

  // 2. Baca dari file konfigurasi
  const configPath = getConfigPath();
  if (existsSync(configPath)) {
    try {
      const raw = readFileSync(configPath, "utf-8");
      const parsed = JSON.parse(raw);
      const validation = validateConfig(parsed);
      if (validation.valid) {
        return {
          api_url: parsed.api_url.trim().replace(/\/+$/, ""),
          api_key: parsed.api_key.trim(),
          model: parsed.model.trim(),
        };
      }
    } catch {}
  }

  return null;
}

export function loadConfig(promptFn: (query: string) => string | null = (q) => prompt(q)): Config {
  const existing = getExistingConfig();
  if (existing) {
    return existing;
  }

  // Konfigurasi interaktif jika belum ada / korup (untuk mode CLI)
  console.log("Konfigurasi awal AI API:");
  const api_url = (promptFn("API URL (contoh: https://api.openai.com/v1): ") || "").trim().replace(/\/+$/, "");
  const api_key = (promptFn("API Key: ") || "").trim();
  const model = (promptFn("Model (contoh: gpt-4o, claude-3-5-sonnet, deepseek-chat): ") || "").trim() || "gpt-4o";

  const cfg: Config = { api_url, api_key, model };
  const validation = validateConfig(cfg);
  if (!validation.valid) {
    throw new Error(`Konfigurasi tidak valid: ${validation.error}`);
  }

  saveConfig(cfg, getConfigPath());
  return cfg;
}
