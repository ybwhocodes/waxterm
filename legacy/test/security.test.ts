import { describe, expect, test } from "bun:test";
import { checkDangerousCommand, validateHost } from "../src/security";

describe("Security Audit: validateHost", () => {
  // Positive Cases
  test("menerima format host yang valid (IP, hostname, user@host)", () => {
    expect(validateHost("user@192.168.1.100").valid).toBe(true);
    expect(validateHost("root@server.dev.internal").valid).toBe(true);
    expect(validateHost("localhost").valid).toBe(true);
    expect(validateHost("my-vps-node1").valid).toBe(true);
    expect(validateHost("admin@10.0.0.1").valid).toBe(true);
  });

  // Negative Cases & Security Attack Vectors
  test("menolak host kosong atau hanya spasi", () => {
    expect(validateHost("").valid).toBe(false);
    expect(validateHost("   ").valid).toBe(false);
  });

  test("menolak SSH argument injection (dimulai dengan '-')", () => {
    const attack1 = validateHost("-oProxyCommand=calc.exe");
    expect(attack1.valid).toBe(false);
    expect(attack1.error).toContain("mencegah SSH option injection");

    const attack2 = validateHost("-v");
    expect(attack2.valid).toBe(false);

    const attack3 = validateHost("--help");
    expect(attack3.valid).toBe(false);
  });

  test("menolak karakter kontrol, null byte, dan newline injection", () => {
    expect(validateHost("user@host\0payload").valid).toBe(false);
    expect(validateHost("user@host\nrm -rf /").valid).toBe(false);
    expect(validateHost("user@host\r").valid).toBe(false);
  });

  test("menolak host dengan spasi tidak sah", () => {
    expect(validateHost("user @host").valid).toBe(false);
    expect(validateHost("host1 host2").valid).toBe(false);
  });
});

describe("Security Audit: checkDangerousCommand", () => {
  // Positive Cases (Perintah aman DevOps normal)
  test("mendeteksi perintah operasional harian sebagai AMAN", () => {
    const safeCommands = [
      "git status",
      "git pull origin main",
      "npm test",
      "docker ps",
      "systemctl status nginx",
      "ls -lah /var/log",
      "cat package.json",
      "bun run build",
      "df -h",
      "free -m",
    ];

    for (const cmd of safeCommands) {
      const res = checkDangerousCommand(cmd);
      expect(res.isDangerous).toBe(false);
      expect(res.requiresStrictConfirm).toBe(false);
    }
  });

  // Negative Cases (Perintah berbahaya & destruktif)
  test("mendeteksi 'rm -rf /' dan variasinya sebagai SANGAT BERBAHAYA", () => {
    const rmAttacks = [
      "rm -rf /",
      "rm -rf /*",
      "rm -fr /",
      "rm -rf ~/",
      "rm -rf $HOME",
      "rm --recursive --force /",
      "rm -rf --no-preserve-root /",
    ];

    for (const cmd of rmAttacks) {
      const res = checkDangerousCommand(cmd);
      expect(res.isDangerous).toBe(true);
      expect(res.requiresStrictConfirm).toBe(true);
      expect(res.reason).toBeDefined();
    }
  });

  test("mendeteksi disk wipe dan mkfs format", () => {
    expect(checkDangerousCommand("mkfs.ext4 /dev/sda1").isDangerous).toBe(true);
    expect(checkDangerousCommand("mkfs /dev/nvme0n1").isDangerous).toBe(true);
    expect(checkDangerousCommand("dd if=/dev/zero of=/dev/sda bs=1M").isDangerous).toBe(true);
  });

  test("mendeteksi fork bomb", () => {
    expect(checkDangerousCommand(":(){ :|:& };:").isDangerous).toBe(true);
  });

  test("mendeteksi mass chmod 777 pada root", () => {
    expect(checkDangerousCommand("chmod -R 777 /").isDangerous).toBe(true);
    expect(checkDangerousCommand("chmod --recursive 777 /").isDangerous).toBe(true);
  });

  test("mendeteksi shutdown dan reboot paksa", () => {
    expect(checkDangerousCommand("shutdown -h now").isDangerous).toBe(true);
    expect(checkDangerousCommand("reboot").isDangerous).toBe(true);
    expect(checkDangerousCommand("init 0").isDangerous).toBe(true);
  });
});
