import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getConfigPath, loadConfig, saveConfig, validateConfig } from "../src/config";
import type { Config } from "../src/types";

describe("Config Audit & Management", () => {
  let testConfigPath: string;
  const originalEnvUrl = process.env.AI_API_URL;
  const originalEnvKey = process.env.AI_API_KEY;
  const originalEnvModel = process.env.AI_MODEL;
  const originalConfigPath = process.env.WAXTERM_CONFIG_PATH;

  beforeEach(() => {
    testConfigPath = join(tmpdir(), `waxterm_test_config_${Date.now()}_${Math.random().toString(36).slice(2)}.json`);
    process.env.WAXTERM_CONFIG_PATH = testConfigPath;
    delete process.env.AI_API_URL;
    delete process.env.AI_API_KEY;
    delete process.env.AI_MODEL;
  });

  afterEach(() => {
    if (existsSync(testConfigPath)) {
      rmSync(testConfigPath, { force: true });
    }
    if (originalEnvUrl) process.env.AI_API_URL = originalEnvUrl;
    else delete process.env.AI_API_URL;
    if (originalEnvKey) process.env.AI_API_KEY = originalEnvKey;
    else delete process.env.AI_API_KEY;
    if (originalEnvModel) process.env.AI_MODEL = originalEnvModel;
    else delete process.env.AI_MODEL;
    if (originalConfigPath) process.env.WAXTERM_CONFIG_PATH = originalConfigPath;
    else delete process.env.WAXTERM_CONFIG_PATH;
  });

  // Positive Cases
  test("validateConfig menerima konfigurasi yang lengkap dan valid", () => {
    const validCfg: Config = {
      api_url: "https://api.openai.com/v1",
      api_key: "sk-proj-1234567890",
      model: "gpt-4o",
    };
    const res = validateConfig(validCfg);
    expect(res.valid).toBe(true);
    expect(res.error).toBeUndefined();
  });

  test("saveConfig dan loadConfig menyimpan dengan izin file aman (mode 0600)", () => {
    const validCfg: Config = {
      api_url: "https://api.openai.com/v1",
      api_key: "sk-secret-token",
      model: "claude-3-5-sonnet",
    };

    saveConfig(validCfg, testConfigPath);
    expect(existsSync(testConfigPath)).toBe(true);

    const stats = statSync(testConfigPath);
    // Mode izin file pada unix (0o600 = user read/write only, tidak boleh world-readable)
    const permissions = stats.mode & 0o777;
    expect(permissions).toBe(0o600);

    const loaded = loadConfig();
    expect(loaded.api_url).toBe("https://api.openai.com/v1");
    expect(loaded.api_key).toBe("sk-secret-token");
    expect(loaded.model).toBe("claude-3-5-sonnet");
  });

  test("loadConfig mengutamakan environment variables jika disetel", () => {
    process.env.AI_API_URL = "http://localhost:11434/v1/";
    process.env.AI_API_KEY = "ollama-local-key";
    process.env.AI_MODEL = "qwen2.5-coder";

    const loaded = loadConfig();
    // Memastikan trailing slash dihilangkan
    expect(loaded.api_url).toBe("http://localhost:11434/v1");
    expect(loaded.api_key).toBe("ollama-local-key");
    expect(loaded.model).toBe("qwen2.5-coder");
  });

  // Negative Cases
  test("validateConfig menolak nilai kosong atau format salah", () => {
    expect(validateConfig(null).valid).toBe(false);
    expect(validateConfig({} as any).valid).toBe(false);
    expect(validateConfig({ api_url: "", api_key: "abc", model: "gpt-4" }).valid).toBe(false);
    expect(validateConfig({ api_url: "https://test.com", api_key: "", model: "gpt-4" }).valid).toBe(false);
    expect(validateConfig({ api_url: "https://test.com", api_key: "abc", model: "" }).valid).toBe(false);
  });

  test("loadConfig menangani file korup dengan meminta konfigurasi ulang", () => {
    // Tulis JSON rusak
    Bun.write(testConfigPath, "{ ini bukan json valid !!! }");

    let promptCount = 0;
    const mockPrompt = (q: string) => {
      promptCount++;
      if (q.includes("API URL")) return "https://mock.api.com/v1";
      if (q.includes("API Key")) return "new-secret-key";
      if (q.includes("Model")) return "deepseek-chat";
      return "";
    };

    const loaded = loadConfig(mockPrompt);
    expect(promptCount).toBe(3);
    expect(loaded.api_key).toBe("new-secret-key");
    expect(loaded.model).toBe("deepseek-chat");
  });
});
