import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const api = {
  // Health
  checkHealth: async () => {
    const res = await client.get('/health');
    return res.data;
  },

  // Stats
  getStats: async () => {
    const res = await client.get('/stats');
    return res.data;
  },

  getOverviewStats: async (windowMinutes = 15) => {
    const res = await client.get('/stats/overview', {
      params: { time_window_minutes: windowMinutes },
    });
    return res.data;
  },

  // Alerts
  getAlerts: async (params = {}) => {
    const res = await client.get('/alerts', { params });
    const totalCount = parseInt(res.headers['x-total-count'] || res.headers['X-Total-Count'] || '0', 10);
    const limit = parseInt(res.headers['x-limit'] || res.headers['X-Limit'] || '50', 10);
    const offset = parseInt(res.headers['x-offset'] || res.headers['X-Offset'] || '0', 10);
    return {
      alerts: res.data,
      totalCount: isNaN(totalCount) ? res.data.length : totalCount,
      limit,
      offset,
    };
  },

  postAlert: async (alertData) => {
    const res = await client.post('/alert', alertData);
    return res.data;
  },

  purgeAlerts: async () => {
    const res = await client.delete('/alerts');
    return res.data;
  },

  // Incidents
  getIncidents: async (windowMinutes = 15) => {
    const res = await client.get('/incidents', {
      params: { time_window_minutes: windowMinutes },
    });
    return res.data;
  },

  getIncidentDetail: async (incidentId, windowMinutes = 15) => {
    const res = await client.get(`/incidents/${encodeURIComponent(incidentId)}`, {
      params: { time_window_minutes: windowMinutes },
    });
    return res.data;
  },

  // Security Check
  analyzeIP: async (payload) => {
    const res = await client.post('/security-check/analyze-ip', payload);
    return res.data;
  },

  parseLog: async (rawLog) => {
    const res = await client.post('/security-check/parse-log', { raw_log: rawLog });
    return res.data;
  },

  // LLM Status & Configuration
  getLLMStatus: async () => {
    const res = await client.get('/llm/status');
    return res.data;
  },

  // Reports & PDF
  generateReport: async (incidentId, windowMinutes = 15, engine = 'auto', model = null) => {
    const params = { time_window_minutes: windowMinutes, engine };
    if (model) params.model = model;
    const res = await client.post(`/incidents/${encodeURIComponent(incidentId)}/report`, null, {
      params,
    });
    return res.data;
  },

  downloadPdfBlob: async (incidentId, windowMinutes = 15, engine = 'auto', model = null) => {
    const params = { time_window_minutes: windowMinutes, engine };
    if (model) params.model = model;
    const res = await client.get(`/incidents/${encodeURIComponent(incidentId)}/pdf`, {
      params,
      responseType: 'blob',
    });
    return res.data;
  },
};

export default api;
