/**
 * JWT API client with automatic token refresh and MFA support.
 *
 * All API calls go through this client which:
 * - Attaches Bearer token from auth store
 * - Intercepts 401 responses and attempts silent refresh
 * - Redirects to login on refresh failure
 */

const BASE_URL = '/api';

let accessToken: string | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

interface RequestOptions extends RequestInit {
  params?: Record<string, string>;
}

class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

export { ApiError };

async function refreshToken(): Promise<string | null> {
  try {
    const resp = await fetch(`${BASE_URL}/auth/refresh`, {
      method: 'POST',
      credentials: 'include', // send refresh_token cookie
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.access_token || null;
  } catch {
    return null;
  }
}

async function request<T = unknown>(
  path: string,
  options: RequestOptions = {}
): Promise<T> {
  const { params, ...init } = options;

  let url = `${BASE_URL}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }

  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string>),
  };

  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  // Don't set Content-Type for FormData (file uploads)
  if (init.body && !(init.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  let resp: Response;
  try {
    resp = await fetch(url, { ...init, headers, credentials: 'include' });
  } catch (err) {
    // Network error — server unreachable, DNS failure, CORS, etc.
    const isDown = err instanceof TypeError && /fetch|network/i.test(err.message);
    throw new ApiError(
      0,
      isDown
        ? `Cannot reach the API server at ${BASE_URL}. Is the server running? (uvicorn server.main:app --port 8000)`
        : `Network error: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // Silent refresh on 401
  if (resp.status === 401 && accessToken) {
    const newToken = await refreshToken();
    if (newToken) {
      accessToken = newToken;
      headers['Authorization'] = `Bearer ${newToken}`;
      const retryResp = await fetch(url, { ...init, headers, credentials: 'include' });
      if (!retryResp.ok) {
        const detail = await retryResp.text().catch(() => 'Request failed');
        throw new ApiError(retryResp.status, detail);
      }
      if (retryResp.status === 204) return undefined as T;
      return retryResp.json();
    }
    // Refresh failed — clear token, redirect to login
    accessToken = null;
    window.location.href = '/login';
    throw new ApiError(401, 'Session expired');
  }

  if (!resp.ok) {
    let detail = 'Request failed';
    try {
      const err = await resp.json();
      const raw = err.detail;
      if (typeof raw === 'string') {
        detail = raw;
      } else if (Array.isArray(raw)) {
        detail = raw.map((e: { msg?: string }) => e.msg || JSON.stringify(e)).join('; ');
      } else {
        detail = JSON.stringify(err);
      }
    } catch {
      detail = await resp.text().catch(() => 'Request failed');
    }
    throw new ApiError(resp.status, detail);
  }

  if (resp.status === 204) return undefined as T;
  return resp.json();
}

// Convenience methods
export const api = {
  get: <T = unknown>(path: string, params?: Record<string, string>) =>
    request<T>(path, { method: 'GET', params }),

  post: <T = unknown>(path: string, body?: unknown) =>
    request<T>(path, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    }),

  put: <T = unknown>(path: string, body?: unknown) =>
    request<T>(path, {
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined,
    }),

  patch: <T = unknown>(path: string, body?: unknown) =>
    request<T>(path, {
      method: 'PATCH',
      body: body ? JSON.stringify(body) : undefined,
    }),

  delete: <T = unknown>(path: string) =>
    request<T>(path, { method: 'DELETE' }),

  upload: <T = unknown>(path: string, file: File) => {
    const form = new FormData();
    form.append('file', file);
    return request<T>(path, { method: 'POST', body: form });
  },
};

export default api;
