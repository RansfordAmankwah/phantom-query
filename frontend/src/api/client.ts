import type {
  Connection,
  SchemaSnapshot,
  NLQueryResponse,
  ValidationResult,
  ExecuteQueryResponse,
  AuthResponse,
  QueryHistoryItem,
  Chat,
  ChatTurn,
  Workspace,
  WorkspaceMember,
  AssignableRole,
  SavedQuery,
  AuditLog,
  AccessLevel,
  ConnectionAccess
} from "../type";

const BASE_URL = (import.meta.env.VITE_API_URL ?? "http://localhost:8000") + "/api";

let authToken: string | null = null;

export function setAuthToken(token: string | null) {
  authToken = token;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail?.message || body.detail || `Request failed: ${res.status}`);
  }
  return res.json();
}

export const api = {
 signup: (email: string, name: string, password: string) =>
  request<AuthResponse>("/auth/signup", {
    method: "POST",
    body: JSON.stringify({ email, name, password }),
  }),

login: (email: string, password: string) =>
  request<AuthResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  }),
 
  listConnections: (workspaceId: string) =>
  request<Connection[]>(`/connections?workspace_id=${workspaceId}`),


 createConnection: (payload: {
  name: string; host: string; port: number; database: string;
  username: string; password: string; use_ssl: boolean; workspace_id: string; db_type: string;
  access_level?: AccessLevel;
}) => request<Connection>("/connections", { method: "POST", body: JSON.stringify(payload) }),


  deleteConnection: (id: string) =>
    request<{ status: string }>(`/connections/${id}`, { method: "DELETE" }),

  getSchema: (connectionId: string) =>
    request<SchemaSnapshot>(`/connections/${connectionId}/schema`),

  

  validateSql: (connectionId: string, sql: string) =>
    request<ValidationResult>("/query/validate", {
      method: "POST",
      body: JSON.stringify({ connection_id: connectionId, sql }),
    }),

  executeSql: (connectionId: string, sql: string, question?: string) =>
  request<ExecuteQueryResponse>("/query/execute", {
    method: "POST",
    body: JSON.stringify({ connection_id: connectionId, sql, question }),
  }),

  summarizeResults: ( question: string, sql: string,columns:string[], rows: unknown[][])  =>
    request<{ summary: string }>("/query/summarize", {
      method: "POST",
      body:JSON.stringify({question, sql, columns, rows })
    }),
  
  retrySql: (connectionId: string, question: string, failedSql: string, errorMessage: string) =>
  request<NLQueryResponse>("/query/retry", {
    method: "POST",
    body: JSON.stringify({
      connection_id: connectionId,
      question,
      failed_sql: failedSql,
      error_message: errorMessage,
    }),
  }),
  getQueryHistory: () => request<QueryHistoryItem[]>("/query/history"),

getQueryStats: () => request<{ queries_executed: number; total_rows_retrieved: number,avg_duration_ms:number }>("/query/stats"),

getChatsForConnection: (connectionId: string) =>
  request<Chat[]>(`/chats/by-connection/${connectionId}`),

createChat: (connectionId: string, workspaceId: string) =>
  request<Chat>("/chats", {
    method: "POST",
    body: JSON.stringify({ connection_id: connectionId, workspace_id: workspaceId }),
  }),

getChatTurns: (chatId: string, since?: string) =>
  request<ChatTurn[]>(`/chats/${chatId}/turns${since ? `?since=${encodeURIComponent(since)}` : ""}`),

addTurn: (chatId: string, question: string) =>
  request<ChatTurn>(`/chats/${chatId}/turns`, {
    method: "POST",
    body: JSON.stringify({ question }),
  }),

listSavedQueries: (workspaceId: string) =>
  request<SavedQuery[]>(`/saved-queries?workspace_id=${workspaceId}`),


checkConnectionHealth: (connectionId: string) =>
  request<{
    healthy: boolean;
    version: string | null;
    latency_ms: number | null;
    ssl_enabled: boolean | null;
    error: string | null;
  }>(`/connections/${connectionId}/health`),

saveQuery: (connectionId: string, workspaceId: string, name: string, question: string, sql: string) =>
  request<SavedQuery>("/saved-queries", {
    method: "POST",
    body: JSON.stringify({ connection_id: connectionId, workspace_id: workspaceId, name, question, sql }),
  }),

deleteSavedQuery: (queryId: string) =>
  request<{ status: string }>(`/saved-queries/${queryId}`, { method: "DELETE" }),
updateTurn: (
  turnId: string,
  updates: { edited_sql?: string; executed?: boolean; row_count?: number; duration_ms?: number }
) =>
  request<ChatTurn>(`/chats/turns/${turnId}`, {
    method: "PATCH",
    body: JSON.stringify(updates),
  }),

deleteTurn: (turnId: string) =>
  request<{ status: string }>(`/chats/turns/${turnId}`, { method: "DELETE"  
  }),

editTurn: (turnId: string, question: string) =>
  request<ChatTurn>(`/chats/turns/${turnId}/edit`, {
    method: "POST",
    body: JSON.stringify({ question }),
  }),

explainSql: (sql: string) =>
  request<{ explanation: string }>("/query/explain", {
    method: "POST",
    body: JSON.stringify({ sql }),
  }),


getUsage: () => request<{
  date: string; prompt_tokens: number; completion_tokens: number;
  total_tokens: number; daily_limit: number; remaining: number;
}>("/query/usage"),

getProfile: () => request<{ id: string; name: string; email: string; created_at: string }>("/user/profile"),

changePassword: (currentPassword: string, newPassword: string) =>
  request<{ status: string }>("/user/change-password", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  }),

listWorkspaces: () => request<Workspace[]>("/workspaces"),

createWorkspace: (name: string) =>
  request<Workspace>("/workspaces", { method: "POST", body: JSON.stringify({ name }) }),

getWorkspaceMembers: (workspaceId: string) =>
  request<WorkspaceMember[]>(`/workspaces/${workspaceId}/members`),

inviteMember: (workspaceId: string, email: string) =>
  request<{ status: string }>(`/workspaces/${workspaceId}/invite`, {
    method: "POST", body: JSON.stringify({ email }),
  }),

removeMember: (workspaceId: string, userId: string) =>
  request<{ status: string }>(`/workspaces/${workspaceId}/members/${userId}`, { method: "DELETE" }),

// Owner-only, enforced server-side. The typed AssignableRole keeps "owner"
// out of the request at compile time too, but the 400 from the API is the
// check that actually matters.
updateMemberRole: (workspaceId: string, userId: string, role: AssignableRole) =>
  request<WorkspaceMember>(`/workspaces/${workspaceId}/members/${userId}/role`, {
    method: "PATCH", body: JSON.stringify({ role }),
  }),

// display_name: null clears the override, falling back to the caller's
// first name (see resolve_author_names() on the backend).
updateDisplayName: (workspaceId: string, displayName: string | null) =>
  request<WorkspaceMember>(`/workspaces/${workspaceId}/members/me`, {
    method: "PATCH", body: JSON.stringify({ display_name: displayName }),
  }),

getAuditLogs: (workspaceId: string, action?: string) =>
  request<AuditLog[]>(
    `/audit-logs?workspace_id=${workspaceId}${action ? `&action=${action}` : ""}`
  ),

// --- Per-connection access (admin or owner only, enforced server-side) ---
// A member calling these gets 403; a member who cannot even see a
// restricted connection gets 404, so the API never confirms it exists.

getConnectionAccess: (connectionId: string) =>
  request<ConnectionAccess>(`/connections/${connectionId}/access`),

updateConnectionAccess: (connectionId: string, accessLevel: AccessLevel) =>
  request<ConnectionAccess>(`/connections/${connectionId}/access`, {
    method: "PATCH", body: JSON.stringify({ access_level: accessLevel }),
  }),

grantConnectionAccess: (connectionId: string, userId: string) =>
  request<ConnectionAccess>(`/connections/${connectionId}/access/grants`, {
    method: "POST", body: JSON.stringify({ user_id: userId }),
  }),

revokeConnectionAccess: (connectionId: string, userId: string) =>
  request<ConnectionAccess>(`/connections/${connectionId}/access/grants/${userId}`, {
    method: "DELETE",
  }),


};