import { mkdir, writeFile } from 'node:fs/promises'
import { join, relative } from 'node:path'
import type { ToolHostContext } from '../ports/tool-host.js'
import {
  isMcpServerTrusted,
  type McpServerDiagnostic
} from '../adapters/tool/mcp-tool-provider.js'
import type {
  McpSearchCatalogRecord,
  McpSearchCatalogState
} from '../adapters/tool/mcp-tool-search.js'
import { ensureReWorkspace } from './re-analysis.js'

export type ReGhidraOperation =
  | 'list_programs'
  | 'program_info'
  | 'list_functions'
  | 'get_function'
  | 'decompile_function'
  | 'disassemble_function'
  | 'xrefs_to'
  | 'xrefs_from'
  | 'callers'
  | 'callees'
  | 'callgraph'
  | 'strings'
  | 'memory_blocks'
  | 'symbols'
  | 'imports'
  | 'exports'
  | 'rename_function'
  | 'set_comment'
  | 'navigate_to'
  | 'trace_dataflow'

export type ReGhidraBridgeOptions = {
  catalog?: McpSearchCatalogState
  diagnostics?: McpServerDiagnostic[]
}

export type ReGhidraToolStatus = {
  ok: true
  ghidraAvailable: boolean
  connectedServers: Array<{
    id: string
    status: McpServerDiagnostic['status']
    toolCount: number
    lastError?: string
  }>
  trustedTools: Array<{
    toolId: string
    serverId: string
    name: string
    title?: string
    description?: string
    matchedOperations: ReGhidraOperation[]
  }>
  availableOperations: ReGhidraOperation[]
  missingOperations: ReGhidraOperation[]
  guidance: string[]
}

export type ReGhidraCallResult = {
  ok: boolean
  ghidraAvailable: boolean
  operation: ReGhidraOperation
  usedTool?: {
    toolId: string
    serverId: string
    name: string
    title?: string
  }
  rawOutputPath?: string
  resultPreview?: string
  result?: unknown
  warnings: string[]
  error?: string
}

const GHIDRA_OPERATIONS: ReGhidraOperation[] = [
  'list_programs',
  'program_info',
  'list_functions',
  'get_function',
  'decompile_function',
  'disassemble_function',
  'xrefs_to',
  'xrefs_from',
  'callers',
  'callees',
  'callgraph',
  'strings',
  'memory_blocks',
  'symbols',
  'imports',
  'exports',
  'rename_function',
  'set_comment',
  'navigate_to',
  'trace_dataflow'
]

const OPERATION_KEYWORDS: Record<ReGhidraOperation, string[]> = {
  list_programs: ['list', 'programs', 'projects', 'open', 'current', 'active'],
  program_info: ['program', 'info', 'metadata', 'current', 'active'],
  list_functions: ['list', 'functions', 'function', 'methods'],
  get_function: ['get', 'function', 'signature', 'details'],
  decompile_function: ['decompile', 'decompiler', 'pseudocode', 'function'],
  disassemble_function: ['disassemble', 'disassembly', 'instructions', 'function'],
  xrefs_to: ['xrefs', 'references', 'to', 'xref', 'incoming'],
  xrefs_from: ['xrefs', 'references', 'from', 'xref', 'outgoing'],
  callers: ['callers', 'called', 'by', 'incoming'],
  callees: ['callees', 'calls', 'outgoing'],
  callgraph: ['callgraph', 'call', 'graph', 'callers', 'callees'],
  strings: ['strings', 'string', 'data'],
  memory_blocks: ['memory', 'blocks', 'segments', 'sections'],
  symbols: ['symbols', 'labels', 'namespaces'],
  imports: ['imports', 'imported', 'external'],
  exports: ['exports', 'exported'],
  rename_function: ['rename', 'function', 'set', 'name'],
  set_comment: ['comment', 'note', 'set', 'plate', 'eol', 'pre'],
  navigate_to: ['navigate', 'goto', 'go', 'address'],
  trace_dataflow: ['dataflow', 'trace', 'flow', 'slicing']
}

export function ghidraStatus(
  options: ReGhidraBridgeOptions,
  context: ToolHostContext
): ReGhidraToolStatus {
  const records = trustedGhidraRecords(options, context)
  const matched = records.map((record) => ({
    toolId: record.toolId,
    serverId: record.serverId,
    name: record.descriptor.name,
    ...(record.descriptor.title ? { title: record.descriptor.title } : {}),
    ...(record.descriptor.description ? { description: clip(record.descriptor.description, 240) } : {}),
    matchedOperations: matchedOperations(record)
  }))
  const availableOperations = uniqueOperations(matched.flatMap((record) => record.matchedOperations))
  const diagnostics = options.diagnostics ?? []
  return {
    ok: true,
    ghidraAvailable: records.length > 0,
    connectedServers: diagnostics
      .filter((diagnostic) => /ghidra/i.test(diagnostic.id) || diagnostic.status === 'connected')
      .map((diagnostic) => ({
        id: diagnostic.id,
        status: diagnostic.status,
        toolCount: diagnostic.toolCount,
        ...(diagnostic.lastError ? { lastError: diagnostic.lastError } : {})
      })),
    trustedTools: matched,
    availableOperations,
    missingOperations: GHIDRA_OPERATIONS.filter((operation) => !availableOperations.includes(operation)),
    guidance: records.length > 0
      ? [
          'Use Ghidra MCP for function-level facts: decompiler output, disassembly, xrefs, symbols, and call graph.',
          'Pull the smallest useful context for the current target, then persist normalized summaries under .re-mode/functions/.'
        ]
      : [
          'No trusted Ghidra MCP tools were discovered for this workspace.',
          'RE Mode can still use local triage, strings, entropy, IOC, capability, behavior graph, and user-provided snippets.',
          'Connect a Ghidra MCP server to enable decompiler/xref/callgraph-backed protected-binary analysis.'
        ]
  }
}

export async function callGhidraOperation(
  options: ReGhidraBridgeOptions,
  context: ToolHostContext,
  operation: ReGhidraOperation,
  args: Record<string, unknown>
): Promise<ReGhidraCallResult> {
  const records = trustedGhidraRecords(options, context)
  if (!records.length) {
    return {
      ok: false,
      ghidraAvailable: false,
      operation,
      warnings: ['No trusted Ghidra MCP tool was discovered for this workspace.'],
      error: 'Ghidra MCP unavailable'
    }
  }
  const record = selectOperationRecord(records, operation)
  if (!record) {
    return {
      ok: false,
      ghidraAvailable: true,
      operation,
      warnings: [`No connected Ghidra MCP tool matched operation ${operation}.`],
      error: 'Ghidra MCP operation unavailable'
    }
  }

  const callArguments = buildOperationArguments(operation, args)
  try {
    const result = await record.client.callTool(
      { name: record.descriptor.name, arguments: callArguments },
      { signal: context.abortSignal, timeout: record.server.timeoutMs }
    )
    const rawOutputPath = await saveGhidraRaw(
      context.workspace,
      operation,
      args,
      record,
      result
    )
    return {
      ok: !isMcpErrorResult(result),
      ghidraAvailable: true,
      operation,
      usedTool: {
        toolId: record.toolId,
        serverId: record.serverId,
        name: record.descriptor.name,
        ...(record.descriptor.title ? { title: record.descriptor.title } : {})
      },
      rawOutputPath,
      resultPreview: summarizeMcpResult(result),
      result: compactMcpResult(result),
      warnings: isMcpErrorResult(result) ? ['Ghidra MCP returned an error result. See rawOutputPath for details.'] : []
    }
  } catch (error) {
    return {
      ok: false,
      ghidraAvailable: true,
      operation,
      usedTool: {
        toolId: record.toolId,
        serverId: record.serverId,
        name: record.descriptor.name,
        ...(record.descriptor.title ? { title: record.descriptor.title } : {})
      },
      warnings: ['Ghidra MCP call failed. Falling back to local RE artifacts or user-provided snippets is recommended.'],
      error: errorMessage(error)
    }
  }
}

function trustedGhidraRecords(
  options: ReGhidraBridgeOptions,
  context: ToolHostContext
): McpSearchCatalogRecord[] {
  const records = options.catalog?.records ?? []
  return records.filter((record) =>
    isMcpServerTrusted(record.server, context.workspace) &&
    isGhidraCandidate(record)
  )
}

function isGhidraCandidate(record: McpSearchCatalogRecord): boolean {
  const text = recordText(record)
  if (/ghidra/i.test(text)) return true
  return /decompile|disassemble|xrefs?|callgraph|program info|memory blocks/i.test(text)
}

function matchedOperations(record: McpSearchCatalogRecord): ReGhidraOperation[] {
  const text = normalize(recordText(record))
  return GHIDRA_OPERATIONS.filter((operation) => {
    const keywords = OPERATION_KEYWORDS[operation]
    const score = keywords.reduce((total, keyword) =>
      total + (text.includes(keyword) ? 1 : 0), 0)
    if (operation === 'xrefs_to' && /xref|reference/.test(text) && /\bto\b|incoming/.test(text)) return true
    if (operation === 'xrefs_from' && /xref|reference/.test(text) && /\bfrom\b|outgoing/.test(text)) return true
    if (operation === 'decompile_function' && /decompil/.test(text)) return true
    if (operation === 'disassemble_function' && /disassembl|instruction/.test(text)) return true
    if (operation === 'rename_function' && /rename/.test(text) && /function/.test(text)) return true
    return score >= Math.min(2, keywords.length)
  })
}

function selectOperationRecord(
  records: McpSearchCatalogRecord[],
  operation: ReGhidraOperation
): McpSearchCatalogRecord | undefined {
  return records
    .map((record) => ({ record, score: operationScore(record, operation) }))
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score)[0]?.record
}

function operationScore(record: McpSearchCatalogRecord, operation: ReGhidraOperation): number {
  const text = normalize(recordText(record))
  const name = normalize(record.descriptor.name)
  const keywords = OPERATION_KEYWORDS[operation]
  let score = /ghidra/.test(text) ? 15 : 4
  for (const keyword of keywords) {
    if (name.includes(keyword)) score += 10
    if (text.includes(keyword)) score += 3
  }
  if (operation === 'decompile_function' && /decompil/.test(text)) score += 30
  if (operation === 'disassemble_function' && /disassembl|instruction/.test(text)) score += 30
  if (operation === 'list_functions' && /list.*function|function.*list|functions/.test(text)) score += 24
  if (operation === 'get_function' && /function/.test(text) && /get|info|signature|details/.test(text)) score += 20
  if ((operation === 'xrefs_to' || operation === 'xrefs_from') && /xref|reference/.test(text)) score += 22
  if (operation === 'callers' && /caller/.test(text)) score += 24
  if (operation === 'callees' && /callee|called function|calls/.test(text)) score += 18
  if (operation === 'callgraph' && /call.?graph/.test(text)) score += 24
  if (operation === 'memory_blocks' && /memory.*block|segment|section/.test(text)) score += 22
  if (operation === 'rename_function' && /rename/.test(text)) score += 24
  if (operation === 'set_comment' && /comment|note/.test(text)) score += 22
  if (operation === 'navigate_to' && /navigate|goto|go_to|address/.test(text)) score += 18
  return score
}

function buildOperationArguments(
  operation: ReGhidraOperation,
  args: Record<string, unknown>
): Record<string, unknown> {
  const explicit = objectArg(args.arguments)
  const out: Record<string, unknown> = { ...explicit }
  const commonKeys = [
    'program',
    'program_id',
    'address',
    'function',
    'function_name',
    'symbol',
    'name',
    'new_name',
    'comment',
    'comment_type',
    'max_items',
    'depth'
  ]
  for (const key of commonKeys) {
    if (args[key] !== undefined && out[key] === undefined) out[key] = args[key]
  }
  if (out.target === undefined) {
    out.target = stringArg(args.address) || stringArg(args.function) || stringArg(args.symbol)
  }
  if (operation === 'rename_function' && out.function === undefined) {
    out.function = stringArg(args.address) || stringArg(args.function_name) || stringArg(args.name)
  }
  if (operation === 'set_comment' && out.address === undefined) {
    out.address = stringArg(args.target) || stringArg(args.function) || stringArg(args.symbol)
  }
  return Object.fromEntries(Object.entries(out).filter(([, value]) => value !== undefined && value !== ''))
}

async function saveGhidraRaw(
  workspaceRoot: string,
  operation: ReGhidraOperation,
  args: Record<string, unknown>,
  record: McpSearchCatalogRecord,
  result: unknown
): Promise<string> {
  const paths = await ensureReWorkspace(workspaceRoot)
  const ghidraRaw = join(paths.raw, 'ghidra')
  await mkdir(ghidraRaw, { recursive: true })
  const targetName = sanitizeFileName(`${operation}-${stringArg(args.address) || stringArg(args.function) || stringArg(args.symbol) || record.descriptor.name}-${Date.now()}.json`)
  const target = join(ghidraRaw, targetName)
  await writeFile(target, `${JSON.stringify({
    operation,
    toolId: record.toolId,
    serverId: record.serverId,
    toolName: record.descriptor.name,
    arguments: buildOperationArguments(operation, args),
    result
  }, null, 2)}\n`, 'utf8')
  return normalizePath(relative(workspaceRoot, target))
}

function summarizeMcpResult(result: unknown): string {
  const text = extractText(result) || JSON.stringify(result)
  return clip(text.replace(/\s+/g, ' ').trim(), 8_000)
}

function compactMcpResult(result: unknown): unknown {
  if (typeof result === 'string') return clip(result, 12_000)
  if (!result || typeof result !== 'object') return result
  const text = extractText(result)
  if (text) {
    return {
      text: clip(text, 12_000),
      truncated: text.length > 12_000,
      isError: isMcpErrorResult(result)
    }
  }
  return clipJson(result, 16_000)
}

function extractText(result: unknown): string {
  if (typeof result === 'string') return result
  if (!result || typeof result !== 'object') return ''
  const obj = result as Record<string, unknown>
  const content = obj.content
  if (Array.isArray(content)) {
    return content
      .map((item) => item && typeof item === 'object' && 'text' in item ? String((item as { text?: unknown }).text ?? '') : '')
      .filter(Boolean)
      .join('\n\n')
  }
  return typeof obj.text === 'string' ? obj.text : ''
}

function clipJson(value: unknown, maxChars: number): unknown {
  const text = JSON.stringify(value)
  if (text.length <= maxChars) return value
  return {
    preview: text.slice(0, maxChars),
    truncated: true
  }
}

function isMcpErrorResult(result: unknown): boolean {
  return Boolean(result && typeof result === 'object' && (result as { isError?: boolean }).isError === true)
}

function uniqueOperations(values: ReGhidraOperation[]): ReGhidraOperation[] {
  return GHIDRA_OPERATIONS.filter((operation) => values.includes(operation))
}

function recordText(record: McpSearchCatalogRecord): string {
  const descriptor = record.descriptor
  return [
    record.serverId,
    record.toolId,
    descriptor.name,
    descriptor.title,
    descriptor.annotations?.title,
    descriptor.description,
    JSON.stringify(descriptor.inputSchema ?? {})
  ].filter(Boolean).join(' ')
}

function objectArg(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

function stringArg(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/[_:/.-]+/g, ' ')
}

function clip(value: string, maxChars: number): string {
  return value.length > maxChars ? `${value.slice(0, maxChars)}...` : value
}

function sanitizeFileName(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 160)
}

function normalizePath(value: string): string {
  return value.replaceAll('\\', '/')
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
