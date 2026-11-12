import type { Config, LlmMessage } from "./types";

export const WAXTERM_TOOLS = [
  {
    type: "function",
    function: {
      name: "run_command",
      description: "Eksekusi perintah shell di VPS remote melalui Rust core SSH",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string", description: "Perintah shell bash" },
        },
        required: ["command"],
      },
    },
  },
];

export function createInitialSystemMessage(host: string): LlmMessage {
  return {
    role: "system",
    content:
      `Kamu asisten DevOps terhubung ke VPS remote \`${host}\`. ` +
      "Jalankan perintah shell via tool `run_command` untuk menyelesaikan instruksi pengguna. " +
      "Analisis hasil keluaran command dan selesaikan masalah jika terjadi error.",
  };
}

export async function callLlm(
  cfg: Config,
  messages: LlmMessage[],
  tools: any[] = WAXTERM_TOOLS,
  options: { timeoutMs?: number; fetchFn?: typeof fetch } = {}
): Promise<any> {
  const timeoutMs = options.timeoutMs ?? 60000;
  const customFetch = options.fetchFn ?? fetch;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await customFetch(`${cfg.api_url}/chat/completions`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${cfg.api_key}`,
        "Content-Type": "application/json",
        "User-Agent": "Waxterm-Bun-Rust/1.0",
      },
      body: JSON.stringify({
        model: cfg.model,
        messages,
        tools: tools && tools.length > 0 ? tools : undefined,
        tool_choice: tools && tools.length > 0 ? "auto" : undefined,
      }),
      signal: controller.signal,
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`HTTP ${res.status}: ${errText}`);
    }

    const json = (await res.json()) as any;
    if (!json || !Array.isArray(json.choices) || json.choices.length === 0) {
      throw new Error("Respon API tidak memiliki 'choices' yang valid.");
    }

    const message = json.choices[0].message;
    if (!message) {
      throw new Error("Pilihan pertama (choices[0]) tidak memiliki data pesan.");
    }

    return message;
  } catch (err: any) {
    if (err.name === "AbortError") {
      throw new Error(`Koneksi LLM timeout setelah ${Math.round(timeoutMs / 1000)} detik.`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
