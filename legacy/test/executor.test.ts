import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { executeViaRust, truncateOutput } from "../src/executor";

describe("Executor Audit: truncateOutput", () => {
  test("tidak memotong teks di bawah batas maksimum", () => {
    const text = "Baris 1\nBaris 2\nBaris 3";
    const result = truncateOutput(text, 1000);
    expect(result.truncated).toBe(false);
    expect(result.text).toBe(text);
  });

  test("memotong teks yang melebihi batas maksimum secara aman", () => {
    const largeText = "A".repeat(500);
    const result = truncateOutput(largeText, 100);
    expect(result.truncated).toBe(true);
    expect(result.text).toContain("Output dipotong");
    expect(result.text.startsWith("A".repeat(100))).toBe(true);
  });
});

describe("Executor Audit: executeViaRust", () => {
  let mockSshScriptPath: string;
  const originalSshBin = process.env.WAXTERM_SSH_BIN;

  beforeAll(() => {
    // Siapkan mock ssh executable untuk pengujian deterministik
    mockSshScriptPath = join(tmpdir(), `mock_ssh_${Date.now()}_${Math.random().toString(36).slice(2)}.sh`);
    const scriptContent = `#!/bin/bash
# Mock SSH behavior based on host or command
cmd=""
for arg in "$@"; do
  cmd="$arg"
done

if [ "$cmd" = "fail_cmd" ]; then
  >&2 echo "Error: command failed on remote host"
  exit 1
elif [ "$cmd" = "ansi_cmd" ]; then
  echo -e "\\033[32mSuccess!\\033[0m All tests passed."
  exit 0
elif [ "$cmd" = "slow_cmd" ]; then
  sleep 3
  echo "finished"
  exit 0
else
  echo "mock_stdout: $cmd"
  exit 0
fi
`;
    writeFileSync(mockSshScriptPath, scriptContent, { mode: 0o755 });
    chmodSync(mockSshScriptPath, 0o755);
    process.env.WAXTERM_SSH_BIN = mockSshScriptPath;
  });

  afterAll(() => {
    if (existsSync(mockSshScriptPath)) {
      rmSync(mockSshScriptPath, { force: true });
    }
    if (originalSshBin) {
      process.env.WAXTERM_SSH_BIN = originalSshBin;
    } else {
      delete process.env.WAXTERM_SSH_BIN;
    }
  });

  // Positive Cases
  test("berhasil menjalankan perintah shell remote (exit code 0)", async () => {
    const result = await executeViaRust("user@vps.internal", "uptime");
    expect(result.exit_code).toBe(0);
    expect(result.stdout).toContain("mock_stdout: uptime");
    expect(result.stderr).toBe("");
  });

  test("berhasil memproses output ANSI escape sequence tanpa merusak JSON", async () => {
    const result = await executeViaRust("user@vps.internal", "ansi_cmd");
    expect(result.exit_code).toBe(0);
    expect(result.stdout).toContain("Success!");
    expect(result.stdout).toContain("All tests passed");
  });

  // Negative Cases
  test("menangani perintah yang gagal dengan exit code bukan 0 dan menangkap stderr", async () => {
    const result = await executeViaRust("user@vps.internal", "fail_cmd");
    expect(result.exit_code).toBe(1);
    expect(result.stderr).toContain("Error: command failed on remote host");
  });

  test("menolak eksekusi jika host diawali flag berbahaya (SSH Option Injection)", async () => {
    const result = await executeViaRust("-oProxyCommand=calc.exe", "ls");
    expect(result.exit_code).toBe(1);
    expect(result.stderr).toContain("mencegah SSH option injection");
  });

  test("menolak eksekusi jika command kosong", async () => {
    const result = await executeViaRust("user@vps.internal", "");
    expect(result.exit_code).toBe(1);
    expect(result.stderr).toContain("Command tidak boleh kosong");
  });

  test("menangani timeout eksekusi dengan membatalkan proses", async () => {
    const result = await executeViaRust("user@vps.internal", "slow_cmd", { timeoutMs: 500 });
    expect(result.exit_code).toBe(-1);
    expect(result.stderr).toContain("Timeout");
  });
});
