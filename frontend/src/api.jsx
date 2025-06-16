import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://192.168.107.192:8000';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 10000,
});

export const startMonitoring = () => api.post('/control/start');
export const stopMonitoring = () => api.post('/control/stop');
export const getStatus = () => api.get('/stats');
export const getSystemInfo = () => api.get('/model/info');
export const getLogs = () => api.get('/alerts/latest');

export default api;
