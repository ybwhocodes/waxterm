import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  addOrUpdateConnection,
  deleteConnection,
  getConnectionById,
  loadConnections,
  recordConnectionUsed,
} from "../src/connections";

describe("Saved SSH Connections Audit", () => {
  let testConnPath: string;
  const originalConnPath = process.env.WAXTERM_CONNECTIONS_PATH;

  beforeEach(() => {
    testConnPath = join(tmpdir(), `waxterm_conn_test_${Date.now()}_${Math.random().toString(36).slice(2)}.json`);
    process.env.WAXTERM_CONNECTIONS_PATH = testConnPath;
  });

  afterEach(() => {
    if (existsSync(testConnPath)) {
      rmSync(testConnPath, { force: true });
    }
    if (originalConnPath) {
      process.env.WAXTERM_CONNECTIONS_PATH = originalConnPath;
    } else {
      delete process.env.WAXTERM_CONNECTIONS_PATH;
    }
  });

  // Positive: Add & Save Connection with 0600 mode
  test("addOrUpdateConnection menyimpan profil server dengan izin file aman (mode 0600)", () => {
    const res = addOrUpdateConnection({
      name: "Production VPS SG",
      host: "192.168.1.100",
      user: "ubuntu",
      port: 22,
      authType: "key",
      keyPath: "~/.ssh/prod_vps.pem",
      notes: "Main Nginx Web Server",
    });

    expect(res.ok).toBe(true);
    expect(res.connection?.id).toBeDefined();
    expect(res.connection?.name).toBe("Production VPS SG");
    expect(res.connection?.port).toBe(22);

    const stats = statSync(testConnPath);
    expect(stats.mode & 0o777).toBe(0o600);

    const list = loadConnections();
    expect(list.length).toBe(1);
    expect(list[0].host).toBe("192.168.1.100");
  });

  // Positive: Update existing connection
  test("addOrUpdateConnection dapat memperbarui profil yang sudah ada", () => {
    const created = addOrUpdateConnection({
      name: "Staging Server",
      host: "staging.example.com",
    });

    const id = created.connection!.id;

    const updated = addOrUpdateConnection({
      id,
      name: "Staging Server Updated",
      host: "staging.example.com",
      port: 2222,
    });

    expect(updated.ok).toBe(true);
    expect(updated.connection?.name).toBe("Staging Server Updated");
    expect(updated.connection?.port).toBe(2222);

    const byId = getConnectionById(id);
    expect(byId?.port).toBe(2222);
  });

  // Positive: Record connection used timestamp
  test("recordConnectionUsed memperbarui lastConnectedAt", () => {
    const created = addOrUpdateConnection({
      name: "DB Server",
      host: "10.0.0.5",
    });
    const id = created.connection!.id;

    recordConnectionUsed(id);
    const byId = getConnectionById(id);
    expect(byId?.lastConnectedAt).toBeDefined();
  });

  // Negative: Reject dangerous injection attempts
  test("addOrUpdateConnection menolak upaya SSH option injection pada host, user, dan keyPath", () => {
    // Malicious host
    const badHost = addOrUpdateConnection({
      host: "-oProxyCommand=calc.exe",
    });
    expect(badHost.ok).toBe(false);
    expect(badHost.error).toContain("mencegah SSH option injection");

    // Malicious user
    const badUser = addOrUpdateConnection({
      host: "192.168.1.1",
      user: "-oBadUser",
    });
    expect(badUser.ok).toBe(false);

    // Malicious key path
    const badKey = addOrUpdateConnection({
      host: "192.168.1.1",
      keyPath: "-iBadKeyOption",
    });
    expect(badKey.ok).toBe(false);
  });

  // Positive & Negative: Delete connection
  test("deleteConnection menghapus profil server dengan benar", () => {
    const c1 = addOrUpdateConnection({ host: "server1.dev" });
    const c2 = addOrUpdateConnection({ host: "server2.dev" });
    expect(loadConnections().length).toBe(2);

    const deleted = deleteConnection(c1.connection!.id);
    expect(deleted).toBe(true);

    const list = loadConnections();
    expect(list.length).toBe(1);
    expect(list[0].host).toBe("server2.dev");
  });
});
