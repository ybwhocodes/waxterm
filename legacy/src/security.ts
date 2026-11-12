import type { DangerousCheckResult } from "./types";

/**
 * Validates a target host string to prevent SSH argument injection
 * and malformed inputs.
 */
export function validateHost(host: string): { valid: boolean; error?: string } {
  if (!host || typeof host !== "string") {
    return { valid: false, error: "Host target tidak boleh kosong." };
  }

  // Reject null bytes, newlines, and carriage returns before trimming
  if (/[\0\r\n]/.test(host)) {
    return {
      valid: false,
      error: "Host target tidak boleh mengandung karakter kontrol (null byte atau newline).",
    };
  }

  const trimmed = host.trim();
  if (trimmed.length === 0) {
    return { valid: false, error: "Host target tidak boleh kosong." };
  }

  // Reject argument injection (e.g. -oProxyCommand=..., -v, --help)
  if (trimmed.startsWith("-")) {
    return {
      valid: false,
      error: "Host target tidak valid: tidak boleh diawali dengan '-' (mencegah SSH option injection).",
    };
  }

  // Hostnames or user@host should not contain unquoted spaces
  if (/\s/.test(trimmed)) {
    return {
      valid: false,
      error: "Host target tidak boleh mengandung spasi.",
    };
  }

  return { valid: true };
}

/**
 * Checks if a shell command poses high risk of system destruction,
 * data loss, or denial of service.
 */
export function checkDangerousCommand(command: string): DangerousCheckResult {
  if (!command || typeof command !== "string") {
    return { isDangerous: false, requiresStrictConfirm: false };
  }

  const trimmed = command.trim();

  // Root or broad directory deletion patterns
  if (/\brm\b/i.test(trimmed)) {
    const isRecursive = /-[a-zA-Z]*r[a-zA-Z]*/i.test(trimmed) || /--recursive/i.test(trimmed);
    const targetsRootOrHome =
      /\s(\/|\/\*|~\/?|\$HOME)(\s|$)/.test(trimmed) ||
      /--no-preserve-root/i.test(trimmed);

    if (isRecursive && targetsRootOrHome) {
      return {
        isDangerous: true,
        reason: "Perintah penghapusan direktori root/home sistem yang destruktif (rm -rf / atau ~).",
        requiresStrictConfirm: true,
      };
    }
  }

  // Disk wipe & formatting patterns
  if (/\bmkfs(\.[a-z0-9]+)?\s+/i.test(trimmed)) {
    return {
      isDangerous: true,
      reason: "Perintah format filesystem disk (mkfs).",
      requiresStrictConfirm: true,
    };
  }

  if (/\bdd\s+.*of=\/dev\/(sd[a-z]|nvme[0-9]n[0-9]|hd[a-z]|disk[0-9])/i.test(trimmed)) {
    return {
      isDangerous: true,
      reason: "Penulisan langsung ke blok partisi disk mentah (dd).",
      requiresStrictConfirm: true,
    };
  }

  // Fork bombs
  if (/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/.test(trimmed)) {
    return {
      isDangerous: true,
      reason: "Fork bomb pattern terdeteksi.",
      requiresStrictConfirm: true,
    };
  }

  // Mass permission destruction
  if (/\bchmod\s+(-[a-zA-Z]*R[a-zA-Z]*|--recursive)\s+(777|000)\s+(\/|\/\*)/i.test(trimmed)) {
    return {
      isDangerous: true,
      reason: "Perubahan hak akses massal secara rekursif pada direktori root (chmod -R 777/000 /).",
      requiresStrictConfirm: true,
    };
  }

  // System shutdown / reboot / halt
  if (/\b(shutdown|reboot|poweroff|halt|init\s+0)\b/i.test(trimmed)) {
    return {
      isDangerous: true,
      reason: "Perintah mematikan atau mereboot server secara paksa.",
      requiresStrictConfirm: true,
    };
  }

  return { isDangerous: false, requiresStrictConfirm: false };
}
