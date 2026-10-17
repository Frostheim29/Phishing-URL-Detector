export interface ScanResponse { url: string; risk_score: number; risk_level: string; verdict: string; model_score: number | null; heuristic_score: number | null; analysis_mode: 'ml_and_heuristic' | 'heuristic_only'; signals: string[]; positive_signals: string[]; negative_signals: string[]; strong_malicious_signals: string[]; analysis: Record<string, unknown>; scanned_at: string }
export interface HistoryItem { id: number; url: string; risk_score: number; risk_level: string; verdict: string; model_score: number | null; heuristic_score: number; analysis_mode: string; scanned_at: string }
export interface HistoryResponse { items: HistoryItem[]; total: number }
export interface BatchScanRequest { urls: string[] }
export interface BatchScanItem { url: string; success: boolean; result: ScanResponse | null; error: string | null }
export interface BatchScanSummary { processed: number; successful: number; failed: number }
export interface BatchScanResponse { items: BatchScanItem[]; summary: BatchScanSummary }
