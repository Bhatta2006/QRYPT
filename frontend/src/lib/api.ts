import axios from 'axios';
import type { paths } from '../types/api';

type ExtractPostRes<T extends keyof paths> = paths[T] extends { post: { responses: { 200: { content: { "application/json": infer R } } } } } ? R : never;

let accessToken: string | null = null;

const api = axios.create({
  baseURL: '/api/v1',
});

api.interceptors.request.use((config) => {
  if (accessToken && config.headers) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

let isRefreshing = false;
let refreshSubscribers: ((token: string) => void)[] = [];

api.interceptors.response.use(
  (res) => res,
  async (err) => {
    const originalConfig = err.config;
    if (err.response?.status === 401 && !originalConfig._retry) {
      if (isRefreshing) {
        return new Promise((resolve) => {
          refreshSubscribers.push((token) => {
            originalConfig.headers.Authorization = `Bearer ${token}`;
            resolve(api(originalConfig));
          });
        });
      }
      
      originalConfig._retry = true;
      isRefreshing = true;
      
      try {
        const { data } = await axios.post<{access_token: string}>('/api/v1/auth/refresh');
        accessToken = data.access_token;
        refreshSubscribers.forEach((cb) => cb(data.access_token));
        originalConfig.headers.Authorization = `Bearer ${data.access_token}`;
        return api(originalConfig);
      } catch (refreshErr) {
        accessToken = null;
        window.dispatchEvent(new CustomEvent('auth:logout'));
        return Promise.reject(err);
      } finally {
        isRefreshing = false;
        refreshSubscribers = [];
      }
    }
    return Promise.reject(err);
  }
);

export const setAccessToken = (token: string | null) => {
  accessToken = token;
};

export const getAccessToken = () => accessToken;

export const apiClient = {
  login: async (data: Record<string, string>) => {
    const res = await api.post<ExtractPostRes<'/api/v1/auth/login'>>('/auth/login', data, {
      headers: { 'Content-Type': 'application/json' }
    });
    return res.data;
  },
  
  generateToken: async (idempotencyKey: string, payloadUrl: string, ttlSeconds: number) => {
    const res = await api.post<unknown>('/tokens', 
      { payload_url: payloadUrl, ttl_seconds: ttlSeconds },
      { headers: { 'Idempotency-Key': idempotencyKey } }
    );
    return res.data;
  },

  listTokens: async (cursor?: string, limit: number = 20) => {
    const params: Record<string, string | number> = { limit };
    if (cursor) params.cursor = cursor;
    const res = await api.get<unknown>('/tokens', { params });
    return res.data;
  },

  revokeToken: async (traceId: string) => {
    const res = await api.post<unknown>(`/tokens/${traceId}/revoke`, { reason: 'Issuer Revocation' });
    return res.data;
  },

  unblockToken: async (traceId: string) => {
    const res = await api.post<unknown>(`/tokens/admin/${traceId}/unblock`);
    return res.data;
  },

  verifyScan: async (deviceId: string, signature: string, timestamp: number, body: {qr_payload: string, timestamp_ms: number}) => {
    const res = await api.post<unknown>('/scan/verify', { svt_raw: body.qr_payload }, {
      headers: {
        'X-Device-Id': deviceId,
        'X-Signature-SHA256': signature,
        'X-Timestamp': timestamp.toString(),
      }
    });
    return res.data;
  },

  getAdminAlerts: async () => {
    const res = await api.get<unknown>('/admin/alerts');
    return res.data;
  },

  getPublicKey: async (traceId: string) => {
    const res = await api.get<unknown>(`/tokens/${traceId}`);
    return res.data;
  },
  
  getScanHeatmap: async (traceId: string, groupby: string = 'hour', days: number = 7) => {
    const res = await api.get<unknown>(`/admin/scan-events/${traceId}`, {
      params: { group_by: groupby, days }
    });
    return res.data;
  }
};
