import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { LocalToolHost } from '../src/adapters/tool/local-tool-host.js'
import { buildReModeLocalTools } from '../src/adapters/tool/re-mode-tools.js'
import {
  analyzeIocs,
  analyzeStrings,
  detectFormat,
  entropy,
  generateReport,
  hashFile,
  reWorkspacePaths,
  type ReResolvedFile
} from '../src/re-mode/re-analysis.js'
import {
  analyzeProtection,
  loadBehaviorGraph,
  saveFunctionSummary,
  updateBehaviorGraph
} from '../src/re-mode/protected-analysis.js'
import { RE_MODE_INSTRUCTION } from '../src/re-mode/re-mode-prompt.js'
import type { ToolHostContext } from '../src/ports/tool-host.js'

function buildContext(workspace: string, threadMode: 'agent' | 'plan' | 're' = 're'): ToolHostContext {
  return {
    threadId: 'thr_1',
    turnId: 'turn_1',
    workspace,
    threadMode,
    approvalPolicy: 'auto',
    abortSignal: new AbortController().signal,
    awaitApproval: async () => 'allow'
  }
}

async function executeTool(
  host: LocalToolHost,
  workspace: string,
  toolName: string,
  args: Record<string, unknown> = {}
) {
  const result = await host.execute(
    {
      callId: `call_${toolName}`,
      toolName,
      arguments: args
    },
    buildContext(workspace, 're')
  )
  expect(result.item.kind).toBe('tool_result')
  if (result.item.kind !== 'tool_result') throw new Error('expected tool_result')
  return result.item.output as Record<string, unknown>
}

describe('RE Mode helpers and tools', () => {
  let workspace: string
  let file: ReResolvedFile
  let fileBuffer: Buffer

  beforeEach(async () => {
    workspace = await mkdtemp(join(tmpdir(), 'kun-re-mode-'))
    fileBuffer = buildSyntheticPe()
    const absolutePath = join(workspace, 'protected-sample.exe')
    await writeFile(absolutePath, fileBuffer)
    file = {
      workspaceRoot: workspace,
      absolutePath,
      relativePath: 'protected-sample.exe'
    }
  })

  afterEach(async () => {
    await rm(workspace, { recursive: true, force: true })
  })

  it('detects format, hashes bytes, extracts strings, extracts IOCs, and estimates entropy', async () => {
    const format = detectFormat(fileBuffer)
    expect(format.format).toBe('PE')
    expect(format.arch).toBe('x86_64')

    const hashes = await hashFile(file.absolutePath)
    expect(hashes.sha256).toBe(createHash('sha256').update(fileBuffer).digest('hex'))

    const strings = await analyzeStrings(file, { include: 'evil', limit: 10 })
    expect(strings.returned).toBeGreaterThan(0)
    expect(strings.strings.some((entry) => entry.value.includes('evil.example'))).toBe(true)
    expect(strings.rawOutputPath).toContain('.re-mode/raw/')

    const iocs = await analyzeIocs(file)
    expect(iocs.iocs.urls).toContain('https://evil.example/path')
    expect(iocs.iocs.registryKeys.some((value) => value.includes('HKCU\\Software\\KunTest'))).toBe(true)
    expect(iocs.iocs.suspiciousApis).toEqual(expect.arrayContaining(['GetProcAddress', 'VirtualProtect']))

    expect(entropy(Buffer.alloc(256, 0))).toBe(0)
    expect(entropy(Buffer.from([...Array(256).keys()]))).toBeGreaterThan(7.9)
  })

  it('builds protected-binary evidence graphs, ranks targets, and writes report artifacts', async () => {
    const result = await analyzeProtection(file, {
      source: 'ghidra-mcp',
      functions: [
        {
          address: '0x1400129A0',
          name: 'sub_1400129A0',
          signature: 'undefined8 sub_1400129A0(byte *bytecode, byte *out)',
          size: 1536,
          callers: ['entry'],
          callees: ['handler_add', 'handler_xor', 'handler_jmp', 'resolver'],
          xrefsTo: ['blob:.vmp1:1536'],
          xrefsFrom: ['artifact:decoded_config'],
          importsUsed: ['GetProcAddress', 'LoadLibraryA', 'VirtualProtect'],
          stringsReferenced: ['https://evil.example/path'],
          constants: ['0x9e3779b9'],
          decompilerText: [
            'while (bytecode[index] != 0xff) {',
            '  opcode = bytecode[index++];',
            '  switch (opcode) { case 1: out[i] ^= key; case 2: out[i] = rol(out[i], 3); }',
            '  goto *handler_table[opcode];',
            '}',
            'GetProcAddress(LoadLibraryA("kernel32.dll"), name);',
            'VirtualProtect(out, size, PAGE_EXECUTE_READWRITE, &oldProtect);'
          ].join('\n'),
          disassemblyText: 'xor al, bl\nrol al, 3\njmp qword ptr [handler_table+rax*8]',
          summary: 'Dispatcher-like decode loop connected to dynamic API resolution and memory permission changes.'
        }
      ],
      xrefs: [
        { from: 'blob:.vmp1:1536', to: '0x1400129A0', kind: 'read', evidence: 'high entropy blob read by dispatcher candidate' },
        { from: '0x1400129A0', to: 'artifact:decoded_config', kind: 'write', evidence: 'decoder writes decoded configuration buffer' }
      ],
      notes: ['Ghidra evidence links the high-entropy section to the dispatcher/decode candidate.']
    })

    expect(result.protectionScore).toBeGreaterThan(0)
    expect(result.evidenceMap.nodes.some((node) => node.source.includes('ghidra-mcp'))).toBe(true)
    expect(result.highValueTargets.some((target) => target.id === 'func:0x1400129A0')).toBe(true)
    expect(result.dynamicApiResolution.length).toBeGreaterThan(0)
    expect(result.behaviorGraphPath).toBe('.re-mode/behavior-graph.json')

    const graph = await loadBehaviorGraph(workspace)
    expect(graph.nodes.some((node) => node.id === 'func:0x1400129A0')).toBe(true)
    expect(graph.edges.some((edge) => edge.from === 'blob:.vmp1:1536' && edge.to === 'func:0x1400129A0')).toBe(true)
    expect(graph.targets[0]?.score).toBeGreaterThan(0)

    await updateBehaviorGraph(workspace, {
      nodes: [
        {
          id: 'artifact:decoded_config',
          type: 'artifact',
          label: 'decoded_config',
          confidence: 'medium',
          source: ['local-re'],
          evidence: ['user confirmed decoded configuration buffer'],
          tags: ['decoded_artifact_candidate']
        }
      ],
      edges: [
        {
          from: 'func:0x1400129A0',
          to: 'artifact:decoded_config',
          relationship: 'decodes_to',
          confidence: 'medium',
          evidence: ['decoder output buffer']
        }
      ],
      knownUnknowns: ['Confirm whether decoded_config is consumed by network code.']
    })
    const updated = await loadBehaviorGraph(workspace)
    expect(updated.knownUnknowns).toContain('Confirm whether decoded_config is consumed by network code.')
    expect(updated.edges.some((edge) => edge.relationship === 'decodes_to')).toBe(true)

    const savedFunction = await saveFunctionSummary(workspace, {
      address: '0x1400129A0',
      name: 'sub_1400129A0',
      suggestedName: 'possible_config_decoder_dispatcher',
      confidence: 'medium',
      tags: ['decoder', 'dispatcher'],
      decompilerSummary: 'Loop decodes bytecode/config and dispatches through a handler table.'
    })
    expect(savedFunction.path).toMatch(/^\.re-mode\/functions\//)
    await expect(readFile(join(workspace, savedFunction.path), 'utf8')).resolves.toContain('possible_config_decoder_dispatcher')

    const report = await generateReport(workspace, file)
    expect(report.markdown).toContain('# Reverse Engineering Report')
    expect(report.markdown).toContain('## Protected / Obfuscated Binary Findings')
    expect(report.reportPath).toBe('.re-mode/report.md')

    const paths = reWorkspacePaths(workspace)
    await expect(readFile(paths.behaviorGraph, 'utf8')).resolves.toContain('0x1400129A0')
  })

  it('advertises RE tools only in RE Mode and degrades Ghidra status gracefully', async () => {
    const host = new LocalToolHost({ tools: buildReModeLocalTools() })
    const agentTools = await host.listTools(buildContext(workspace, 'agent'))
    expect(agentTools.some((tool) => tool.name === 're_triage')).toBe(false)

    const reTools = await host.listTools(buildContext(workspace, 're'))
    const names = new Set(reTools.map((tool) => tool.name))
    expect(names.has('re_triage')).toBe(true)
    expect(names.has('re_protection_indicators')).toBe(true)
    expect(names.has('re_ghidra_status')).toBe(true)

    const ghidraStatus = await executeTool(host, workspace, 're_ghidra_status')
    expect(ghidraStatus.ok).toBe(true)
    expect(ghidraStatus.ghidraAvailable).toBe(false)
    expect(String((ghidraStatus.guidance as string[])[0])).toContain('No trusted Ghidra MCP tools')

    const availability = await executeTool(host, workspace, 're_tool_availability')
    expect(availability.ok).toBe(true)
    expect(Array.isArray(availability.available)).toBe(true)
    expect(Array.isArray(availability.missing)).toBe(true)
  })

  it('loads prompt instructions for Ghidra-aware protected binary analysis', () => {
    expect(RE_MODE_INSTRUCTION).toContain('Ghidra MCP')
    expect(RE_MODE_INSTRUCTION).toContain('Protected Binary Analysis')
    expect(RE_MODE_INSTRUCTION).toContain('.re-mode/behavior-graph.json')
    expect(RE_MODE_INSTRUCTION).toContain('Known unknowns')
  })
})

function buildSyntheticPe(): Buffer {
  const buffer = Buffer.alloc(0x800, 0)
  buffer.write('MZ', 0, 'ascii')
  buffer.writeUInt32LE(0x80, 0x3c)
  buffer.write('PE\0\0', 0x80, 'ascii')
  buffer.writeUInt16LE(0x8664, 0x84)
  buffer.writeUInt16LE(2, 0x86)
  buffer.writeUInt16LE(0xf0, 0x94)

  const optional = 0x98
  buffer.writeUInt16LE(0x20b, optional)
  buffer.writeUInt32LE(0x1000, optional + 16)
  buffer.writeBigUInt64LE(0x140000000n, optional + 24)
  buffer.writeUInt16LE(3, optional + 0x5c)

  writeSection(buffer, 0x188, '.text', 0x1000, 0x240, 0x400, 0x200, 0x60000020)
  writeSection(buffer, 0x1b0, '.vmp1', 0x2000, 0x200, 0x600, 0x200, 0xe0000020)

  buffer.write([
    'GetProcAddress LoadLibraryA VirtualProtect IsDebuggerPresent',
    'https://evil.example/path',
    'HKCU\\Software\\KunTest',
    'C:\\Users\\Public\\svchost.exe',
    'powershell -nop -w hidden',
    'opcode dispatcher handler bytecode vm_loop',
    'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo='
  ].join('\0'), 0x420, 'ascii')

  for (let index = 0; index < 0x200; index += 1) {
    buffer[0x600 + index] = index & 0xff
  }

  return buffer
}

function writeSection(
  buffer: Buffer,
  offset: number,
  name: string,
  virtualAddress: number,
  virtualSize: number,
  rawOffset: number,
  rawSize: number,
  characteristics: number
): void {
  buffer.write(name, offset, 'ascii')
  buffer.writeUInt32LE(virtualSize, offset + 8)
  buffer.writeUInt32LE(virtualAddress, offset + 12)
  buffer.writeUInt32LE(rawSize, offset + 16)
  buffer.writeUInt32LE(rawOffset, offset + 20)
  buffer.writeUInt32LE(characteristics, offset + 36)
}
