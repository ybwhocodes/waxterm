import { existsSync } from "node:fs";
import { join } from "node:path";
import { validateHost } from "./security";
import type { CommandResult } from "./types";

const DEFAULT_MAX_OUTPUT_BYTES = 50 * 1024; // 50 KB

export function getProjectRoot(): string {
  return join(import.meta.dir, "..");
}

export function findCoreBinaryPath(): string | null {
  const root = getProjectRoot();
  const releaseBin = join(root, "target", "release", "waxterm-core");
  if (existsSync(releaseBin)) {
    return releaseBin;
  }
  const debugBin = join(root, "target", "debug", "waxterm-core");
  if (existsSync(debugBin)) {
    return debugBin;
  }
  return null;
}

export function truncateOutput(text: string, maxBytes: number = DEFAULT_MAX_OUTPUT_BYTES): { text: string; truncated: boolean } {
  const buf = Buffer.from(text, "utf-8");
  if (buf.length <= maxBytes) {
    return { text, truncated: false };
  }
  const truncatedBuf = buf.subarray(0, maxBytes);
  const truncatedText = truncatedBuf.toString("utf-8");
  return {
    text: `${truncatedText}\n... [Output dipotong: melebihi batas ${Math.round(maxBytes / 1024)} KB]`,
    truncated: true,
  };
}

export interface ExecuteOptions {
  maxOutputBytes?: number;
  timeoutMs?: number;
  port?: number;
  keyPath?: string;
  password?: string;
}

export async function executeViaRust(
  host: string,
  command: string,
  options: ExecuteOptions = {}
): Promise<CommandResult> {
  const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const timeoutMs = options.timeoutMs ?? 30000;

  // Validasi awal host di sisi TypeScript
  const hostValidation = validateHost(host);
  if (!hostValidation.valid) {
    return {
      exit_code: 1,
      stdout: "",
      stderr: hostValidation.error || "Host target tidak valid.",
    };
  }

  if (!command || command.trim() === "") {
    return {
      exit_code: 1,
      stdout: "",
      stderr: "Command tidak boleh kosong.",
    };
  }

  const projectRoot = getProjectRoot();
  const binaryPath = findCoreBinaryPath();

  const spawnArgs: string[] = binaryPath
    ? [binaryPath, host, command]
    : ["cargo", "run", "--quiet", "--", host, command];

  if (options.port) {
    spawnArgs.push(String(options.port));
  } else if (options.keyPath) {
    spawnArgs.push(""); // empty port slot
  }

  if (options.keyPath) {
    spawnArgs.push(options.keyPath);
  }

  try {
    const spawnEnv = {
      ...process.env,
      ...(options.password ? { WAXTERM_SSH_PASSWORD: options.password } : {}),
    };

    const proc = Bun.spawn(spawnArgs, {
      cwd: projectRoot,
      env: spawnEnv,
      stdout: "pipe",
      stderr: "pipe",
    });

    // Timeout guard
    let timer: any;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        try {
          proc.kill(9);
        } catch {
          // Process might already be closed
        }
        reject(new Error(`Timeout: Eksekusi SSH melebihi ${Math.round(timeoutMs / 1000)} detik.`));
      }, timeoutMs);
    });

    const executionPromise = (async () => {
      const stdoutRaw = await new Response(proc.stdout).text();
      const stderrRaw = await new Response(proc.stderr).text();
      await proc.exited;
      return { stdoutRaw, stderrRaw, exitCode: proc.exitCode };
    })();

    const { stdoutRaw, stderrRaw, exitCode } = await Promise.race([executionPromise, timeoutPromise]).finally(() => {
      clearTimeout(timer);
    });

    let parsedResult: CommandResult;
    try {
      parsedResult = JSON.parse(stdoutRaw.trim());
    } catch {
      parsedResult = {
        exit_code: exitCode ?? -1,
        stdout: stdoutRaw.trim(),
        stderr: stderrRaw.trim(),
      };
    }

    // Terapkan batas ukuran output agar aman untuk context window LLM
    const stdoutTruncated = truncateOutput(parsedResult.stdout || "", maxOutputBytes);
    const stderrTruncated = truncateOutput(parsedResult.stderr || "", maxOutputBytes);

    // Bersihkan notice post-quantum OpenSSH agar tidak mengacaukan log
    const cleanStderr = stderrTruncated.text
      .replace(/\*\* WARNING: connection is not using a post-quantum key exchange algorithm\.\s*\n?/g, "")
      .replace(/\*\* This session may be vulnerable to "store now, decrypt later" attacks\.\s*\n?/g, "")
      .replace(/\*\* The server may need to be upgraded\. See https:\/\/openssh\.com\/pq\.html\s*\n?/g, "")
      .trim();

    return {
      exit_code: parsedResult.exit_code,
      stdout: stdoutTruncated.text,
      stderr: cleanStderr,
      truncated: stdoutTruncated.truncated || stderrTruncated.truncated,
    };
  } catch (err: any) {
    return {
      exit_code: -1,
      stdout: "",
      stderr: err.message || "Gagal mengeksekusi waxterm-core.",
    };
  }
}
