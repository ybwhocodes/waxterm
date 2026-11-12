import { describe, expect, test } from "bun:test";
import { callLlm, createInitialSystemMessage } from "../src/llm";
import type { Config } from "../src/types";

describe("LLM Integration Audit", () => {
  const dummyCfg: Config = {
    api_url: "https://mock-llm.example.com/v1",
    api_key: "dummy-key",
    model: "mock-model",
  };

  test("createInitialSystemMessage memuat host target dengan benar", () => {
    const msg = createInitialSystemMessage("user@192.168.1.10");
    expect(msg.role).toBe("system");
    expect(msg.content).toContain("user@192.168.1.10");
    expect(msg.content).toContain("run_command");
  });

  // Positive Case: Respon LLM sukses dengan tool_calls
  test("berhasil memproses respon LLM dengan tool_calls", async () => {
    const mockFetch = async () => {
      return new Response(
        JSON.stringify({
          choices: [
            {
              message: {
                role: "assistant",
                content: null,
                tool_calls: [
                  {
                    id: "call_abc123",
                    type: "function",
                    function: {
                      name: "run_command",
                      arguments: '{"command":"docker ps"}',
                    },
                  },
                ],
              },
            },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    const res = await callLlm(dummyCfg, [{ role: "user", content: "cek kontainer docker" }], [], {
      fetchFn: mockFetch as any,
    });

    expect(res.role).toBe("assistant");
    expect(res.tool_calls.length).toBe(1);
    expect(res.tool_calls[0].function.name).toBe("run_command");
    const args = JSON.parse(res.tool_calls[0].function.arguments);
    expect(args.command).toBe("docker ps");
  });

  // Negative Cases
  test("menangani HTTP 401 Unauthorized dari provider AI", async () => {
    const mockFetch = async () => {
      return new Response("Invalid API key provided", { status: 401 });
    };

    expect(
      callLlm(dummyCfg, [{ role: "user", content: "halo" }], [], {
        fetchFn: mockFetch as any,
      })
    ).rejects.toThrow("HTTP 401");
  });

  test("menangani HTTP 500 Internal Server Error", async () => {
    const mockFetch = async () => {
      return new Response("Server overload", { status: 500 });
    };

    expect(
      callLlm(dummyCfg, [{ role: "user", content: "halo" }], [], {
        fetchFn: mockFetch as any,
      })
    ).rejects.toThrow("HTTP 500");
  });

  test("menolak respon yang tidak memiliki pilihan (empty choices)", async () => {
    const mockFetch = async () => {
      return new Response(JSON.stringify({ choices: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    expect(
      callLlm(dummyCfg, [{ role: "user", content: "halo" }], [], {
        fetchFn: mockFetch as any,
      })
    ).rejects.toThrow("Respon API tidak memiliki 'choices' yang valid");
  });

  test("menangani network timeout", async () => {
    const mockFetch = async (_url: string, init?: any) => {
      return new Promise<Response>((_, reject) => {
        if (init?.signal) {
          init.signal.addEventListener("abort", () => {
            const err = new Error("The operation was aborted");
            err.name = "AbortError";
            reject(err);
          });
        }
      });
    };

    expect(
      callLlm(dummyCfg, [{ role: "user", content: "halo" }], [], {
        fetchFn: mockFetch as any,
        timeoutMs: 100,
      })
    ).rejects.toThrow("timeout");
  });
});
