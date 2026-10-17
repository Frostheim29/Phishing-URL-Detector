import type { BatchScanResponse, HistoryResponse, ScanResponse } from './types'
const configured = import.meta.env.VITE_API_BASE_URL?.trim()
const base = configured && configured !== 'http://127.0.0.1:8000' ? configured.replace(/\/$/, '') : ''
export class ApiError extends Error {}
async function request<T>(path: string, init?: RequestInit): Promise<T> { let response: Response; try { response = await fetch(`${base}${path}`, { headers: { 'Content-Type': 'application/json', ...init?.headers }, ...init }) } catch { throw new ApiError('Unable to reach the API. Confirm the backend is running.') }; if (!response.ok) { const body = await response.json().catch(() => null); throw new ApiError(body?.detail || `Request failed (${response.status}).`) }; return response.json() as Promise<T> }
export const getHistory = (limit = 50) => request<HistoryResponse>(`/api/history?limit=${limit}`)
export const scanUrl = (url: string) => request<ScanResponse>('/api/scan', { method: 'POST', body: JSON.stringify({ url }) })
export const scanUrlsBatch = (urls: string[]) => request<BatchScanResponse>('/api/scan/batch', { method: 'POST', body: JSON.stringify({ urls }) })
