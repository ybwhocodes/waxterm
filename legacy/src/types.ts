export type UserRole = "super_admin" | "admin";

export interface User {
  id: string;
  username: string;
  name: string;
  role: UserRole;
  passwordHash: string;
  createdAt: string;
  updatedAt: string;
}

export type SafeUser = Omit<User, "passwordHash">;

export interface Session {
  token: string;
  userId: string;
  username: string;
  name: string;
  role: UserRole;
  createdAt: number;
  expiresAt: number;
}

export interface SshConnectionProfile {
  id: string;
  name: string;
  host: string;
  user?: string;
  port: number;
  authType: "key" | "password" | "agent";
  keyPath?: string;
  password?: string;
  notes?: string;
  createdBy?: string;
  createdAt?: string;
  lastConnectedAt?: string;
}

export interface Config {
  api_url: string;
  api_key: string;
  model: string;
}

export interface CommandResult {
  exit_code: number;
  stdout: string;
  stderr: string;
  truncated?: boolean;
}

export interface ToolCall {
  id: string;
  type: string;
  function: {
    name: string;
    arguments: string;
  };
}

export interface LlmMessage {
  role: "system" | "user" | "assistant" | "tool";
  content?: string | null;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
}

export interface DangerousCheckResult {
  isDangerous: boolean;
  reason?: string;
  requiresStrictConfirm: boolean;
}
