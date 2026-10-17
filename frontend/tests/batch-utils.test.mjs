import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import ts from 'typescript'

const source = await readFile(new URL('../src/batchUtils.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText
const utils = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)

test('CSV export escapes commas, quotes, and line breaks', () => {
  const csv = utils.batchResultsCsv([{ url: 'https://example.com/a,b', success: false, result: null, error: 'Could not parse "unsafe"\ninput' }])
  assert.match(csv, /"https:\/\/example\.com\/a,b"/)
  assert.match(csv, /"Could not parse ""unsafe""\ninput"/)
  assert.match(csv, /,,,,,,,,false,/)
})

test('CSV imports prefer url and remove duplicate URLs in caller flow', () => {
  assert.deepEqual(utils.parseCsv('name,url\none,https://one.example\ntwo,https://two.example'), ['https://one.example', 'https://two.example'])
  assert.deepEqual(utils.uniqueUrls([' https://one.example ', 'https://ONE.example', '', 'https://two.example']), ['https://one.example', 'https://two.example'])
})
