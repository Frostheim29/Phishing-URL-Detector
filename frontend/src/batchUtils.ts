import type { BatchScanItem } from './types'

export const MAX_BATCH_URLS = 100

export function uniqueUrls(values: string[]): string[] {
  const seen = new Set<string>()
  return values.reduce<string[]>((urls, value) => {
    const url = value.trim()
    const key = url.toLowerCase()
    if (url && !seen.has(key)) { seen.add(key); urls.push(url) }
    return urls
  }, [])
}

export function parseCsv(text: string): string[] {
  const rows: string[][] = [[]]
  let value = '', quoted = false
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]
    if (char === '"') {
      if (quoted && text[index + 1] === '"') { value += '"'; index += 1 } else quoted = !quoted
    } else if (char === ',' && !quoted) { rows.at(-1)?.push(value); value = ''
    } else if ((char === '\n' || char === '\r') && !quoted) {
      if (char === '\r' && text[index + 1] === '\n') index += 1
      rows.at(-1)?.push(value); value = ''; rows.push([])
    } else value += char
  }
  rows.at(-1)?.push(value)
  const populated = rows.filter(row => row.some(cell => cell.trim()))
  if (!populated.length) return []
  const [headers, ...data] = populated
  const namedUrlColumn = headers.findIndex(header => header.trim().toLowerCase() === 'url')
  const usableColumn = headers.findIndex((_, column) => data.some(row => row[column]?.trim()))
  const column = namedUrlColumn >= 0 ? namedUrlColumn : usableColumn
  return column < 0 ? [] : data.map(row => row[column] ?? '')
}

export function csvEscape(value: unknown): string {
  const text = value == null ? '' : String(value)
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

export function batchResultsCsv(items: BatchScanItem[]): string {
  const columns = ['url', 'risk_score', 'risk_level', 'verdict', 'model_score', 'heuristic_score', 'analysis_mode', 'scanned_at', 'success', 'error']
  const rows = items.map(item => {
    const result = item.result
    return [item.url, result?.risk_score, result?.risk_level, result?.verdict, result?.model_score, result?.heuristic_score, result?.analysis_mode, result?.scanned_at, item.success, item.error]
  })
  return [columns, ...rows].map(row => row.map(csvEscape).join(',')).join('\r\n')
}
