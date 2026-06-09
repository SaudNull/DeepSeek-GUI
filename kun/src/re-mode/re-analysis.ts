import { createHash } from 'node:crypto'
import { createReadStream, existsSync } from 'node:fs'
import { mkdir, open, readFile, stat, writeFile } from 'node:fs/promises'
import { basename, extname, join, relative } from 'node:path'
import { spawnSync } from 'node:child_process'

export type ReResolvedFile = {
  workspaceRoot: string
  absolutePath: string
  relativePath: string
}

export type ReHashResult = {
  md5: string
  sha1: string
  sha256: string
  sha512: string
}

export type ReFormatResult = {
  format: 'PE' | 'ELF' | 'Mach-O' | 'APK' | 'ZIP' | 'Raw' | 'Unknown'
  arch?: string
  bitness?: 32 | 64
  endian?: 'little' | 'big'
  subtype?: string
  details: Record<string, unknown>
  warnings: string[]
}

export type ReSection = {
  name: string
  type?: string
  virtualAddress?: string
  virtualSize?: number
  rawOffset?: number
  rawSize?: number
  entropy?: number
  flags?: string[]
  characteristics?: string
}

export type ReImport = {
  library: string
  symbols: string[]
}

export type ReExport = {
  name: string
  address?: string
  ordinal?: number
}

export type ReStringRecord = {
  offset: number
  encoding: 'ascii' | 'utf16le'
  value: string
  tags?: string[]
}

export type ReIocs = {
  urls: string[]
  domains: string[]
  ipv4: string[]
  ipv6: string[]
  emails: string[]
  registryKeys: string[]
  windowsPaths: string[]
  unixPaths: string[]
  fileNames: string[]
  mutexes: string[]
  userAgents: string[]
  powershellCommands: string[]
  shellCommands: string[]
  base64Blobs: string[]
  hexBlobs: string[]
  cryptoConstants: string[]
  suspiciousApis: string[]
}

export type ReCapability = {
  capability: string
  confidence: 'low' | 'medium' | 'high'
  evidence: string[]
}

export type ReSampleState = {
  path: string
  fileName: string
  size?: number
  hashes?: ReHashResult
  format?: ReFormatResult
  sections?: ReSection[]
  imports?: ReImport[]
  exports?: ReExport[]
  entropy?: {
    overall: number
    windowSize: number
    highestWindows: Array<{ offset: number; entropy: number }>
  }
  iocs?: ReIocs
  capabilities?: ReCapability[]
  packerIndicators?: Array<{ indicator: string; confidence: 'low' | 'medium' | 'high'; evidence: string[] }>
  cryptoCandidates?: Record<string, unknown>
  toolSummaries?: Record<string, unknown>
  recommendedTargets?: string[]
  updatedAt: string
}

export type ReAnalysisState = {
  version: 1
  currentSample?: string
  samples: Record<string, ReSampleState>
  hypotheses: string[]
  recommendedTargets: string[]
  updatedAt: string
}

export type ReSymbolsState = {
  version: 1
  functions: Record<string, {
    suggestedName?: string
    userName?: string
    notes?: string
    confidence?: 'low' | 'medium' | 'high'
  }>
  variables: Record<string, {
    suggestedName?: string
    userName?: string
    notes?: string
    confidence?: 'low' | 'medium' | 'high'
  }>
  labels: Record<string, {
    name: string
    notes?: string
    confidence?: 'low' | 'medium' | 'high'
  }>
  updatedAt: string
}

const DEFAULT_MAX_ANALYSIS_BYTES = 128 * 1024 * 1024
const DEFAULT_MAX_STRINGS = 50_000
const DEFAULT_RETURN_LIMIT = 200

const EMPTY_IOCS: ReIocs = {
  urls: [],
  domains: [],
  ipv4: [],
  ipv6: [],
  emails: [],
  registryKeys: [],
  windowsPaths: [],
  unixPaths: [],
  fileNames: [],
  mutexes: [],
  userAgents: [],
  powershellCommands: [],
  shellCommands: [],
  base64Blobs: [],
  hexBlobs: [],
  cryptoConstants: [],
  suspiciousApis: []
}

export function reWorkspacePaths(workspaceRoot: string): {
  root: string
  analysis: string
  symbols: string
  iocs: string
  notes: string
  report: string
  behaviorGraph: string
  raw: string
  functions: string
  diffs: string
} {
  const root = join(workspaceRoot, '.re-mode')
  return {
    root,
    analysis: join(root, 'analysis.json'),
    symbols: join(root, 'symbols.json'),
    iocs: join(root, 'iocs.json'),
    notes: join(root, 'notes.md'),
    report: join(root, 'report.md'),
    behaviorGraph: join(root, 'behavior-graph.json'),
    raw: join(root, 'raw'),
    functions: join(root, 'functions'),
    diffs: join(root, 'diffs')
  }
}

export async function ensureReWorkspace(workspaceRoot: string): Promise<ReturnType<typeof reWorkspacePaths>> {
  const paths = reWorkspacePaths(workspaceRoot)
  await Promise.all([
    mkdir(paths.root, { recursive: true }),
    mkdir(paths.raw, { recursive: true }),
    mkdir(paths.functions, { recursive: true }),
    mkdir(paths.diffs, { recursive: true })
  ])
  if (!existsSync(paths.notes)) {
    await writeFile(paths.notes, '# Reverse Engineering Notes\n', 'utf8')
  }
  if (!existsSync(paths.symbols)) {
    await writeJson(paths.symbols, emptySymbolsState())
  }
  if (!existsSync(paths.iocs)) {
    await writeJson(paths.iocs, EMPTY_IOCS)
  }
  if (!existsSync(paths.analysis)) {
    await writeJson(paths.analysis, emptyAnalysisState())
  }
  return paths
}

export async function loadAnalysisState(workspaceRoot: string): Promise<ReAnalysisState> {
  const paths = await ensureReWorkspace(workspaceRoot)
  return normalizeAnalysisState(await readJson(paths.analysis).catch(() => emptyAnalysisState()))
}

export async function saveAnalysisState(workspaceRoot: string, state: ReAnalysisState): Promise<void> {
  const paths = await ensureReWorkspace(workspaceRoot)
  await writeJson(paths.analysis, normalizeAnalysisState({ ...state, updatedAt: nowIso() }))
}

export async function loadSymbolsState(workspaceRoot: string): Promise<ReSymbolsState> {
  const paths = await ensureReWorkspace(workspaceRoot)
  return normalizeSymbolsState(await readJson(paths.symbols).catch(() => emptySymbolsState()))
}

export async function saveSymbolsState(workspaceRoot: string, state: ReSymbolsState): Promise<void> {
  const paths = await ensureReWorkspace(workspaceRoot)
  await writeJson(paths.symbols, normalizeSymbolsState({ ...state, updatedAt: nowIso() }))
}

export async function updateSampleState(
  file: ReResolvedFile,
  patch: Partial<ReSampleState> & { hashes?: ReHashResult }
): Promise<ReAnalysisState> {
  const state = await loadAnalysisState(file.workspaceRoot)
  const key = patch.hashes?.sha256 ?? state.currentSample ?? file.relativePath
  const current = state.samples[key] ?? {
    path: normalizePath(file.relativePath),
    fileName: basename(file.absolutePath),
    updatedAt: nowIso()
  }
  const sample: ReSampleState = {
    ...current,
    ...patch,
    path: normalizePath(file.relativePath),
    fileName: basename(file.absolutePath),
    updatedAt: nowIso()
  }
  state.currentSample = key
  state.samples[key] = sample
  state.recommendedTargets = sample.recommendedTargets ?? state.recommendedTargets
  state.updatedAt = nowIso()
  await saveAnalysisState(file.workspaceRoot, state)
  return state
}

export async function saveRawOutput(
  workspaceRoot: string,
  kind: string,
  fileRelativePath: string,
  output: unknown,
  extension = 'json'
): Promise<string> {
  const paths = await ensureReWorkspace(workspaceRoot)
  const safeBase = sanitizeFileName(`${kind}-${fileRelativePath || 'workspace'}-${Date.now()}.${extension}`)
  const target = join(paths.raw, safeBase)
  if (typeof output === 'string') {
    await writeFile(target, output, 'utf8')
  } else {
    await writeJson(target, output)
  }
  return normalizePath(relative(workspaceRoot, target))
}

export async function readBinarySample(
  absolutePath: string,
  maxBytes = DEFAULT_MAX_ANALYSIS_BYTES
): Promise<{ buffer: Buffer; size: number; truncated: boolean }> {
  const st = await stat(absolutePath)
  const size = st.size
  if (size <= maxBytes) {
    return { buffer: await readFile(absolutePath), size, truncated: false }
  }
  const handle = await open(absolutePath, 'r')
  try {
    const buffer = Buffer.allocUnsafe(maxBytes)
    const result = await handle.read(buffer, 0, maxBytes, 0)
    return { buffer: buffer.subarray(0, result.bytesRead), size, truncated: true }
  } finally {
    await handle.close()
  }
}

export async function hashFile(absolutePath: string): Promise<ReHashResult> {
  const hashes = {
    md5: createHash('md5'),
    sha1: createHash('sha1'),
    sha256: createHash('sha256'),
    sha512: createHash('sha512')
  }
  await new Promise<void>((resolvePromise, reject) => {
    const stream = createReadStream(absolutePath)
    stream.on('data', (chunk: Buffer) => {
      hashes.md5.update(chunk)
      hashes.sha1.update(chunk)
      hashes.sha256.update(chunk)
      hashes.sha512.update(chunk)
    })
    stream.on('error', reject)
    stream.on('end', resolvePromise)
  })
  return {
    md5: hashes.md5.digest('hex'),
    sha1: hashes.sha1.digest('hex'),
    sha256: hashes.sha256.digest('hex'),
    sha512: hashes.sha512.digest('hex')
  }
}

export async function analyzeFileInfo(file: ReResolvedFile): Promise<{
  ok: true
  file: string
  fileName: string
  size: number
  extension: string
  modifiedAt?: string
  hashes: ReHashResult
  format: ReFormatResult
  warnings: string[]
}> {
  const [st, hashes, sample] = await Promise.all([
    stat(file.absolutePath),
    hashFile(file.absolutePath),
    readBinarySample(file.absolutePath, 16 * 1024 * 1024)
  ])
  const format = detectFormat(sample.buffer)
  const warnings = [...format.warnings]
  if (sample.truncated) warnings.push('format detection used the first 16 MiB only')
  await updateSampleState(file, {
    size: st.size,
    hashes,
    format
  })
  return {
    ok: true,
    file: normalizePath(file.relativePath),
    fileName: basename(file.absolutePath),
    size: st.size,
    extension: extname(file.absolutePath).toLowerCase(),
    modifiedAt: st.mtime.toISOString(),
    hashes,
    format,
    warnings
  }
}

export function detectFormat(buffer: Buffer): ReFormatResult {
  const warnings: string[] = []
  if (buffer.length < 4) return { format: 'Unknown', details: {}, warnings: ['file is too small to identify'] }
  const pe = parsePeHeaders(buffer)
  if (pe) {
    return {
      format: 'PE',
      arch: pe.arch,
      bitness: pe.bitness,
      endian: 'little',
      subtype: pe.subsystem,
      details: {
        machine: pe.machineHex,
        timestamp: pe.timestamp,
        imageBase: hex(pe.imageBase),
        entryPointRva: hex(pe.entryPointRva),
        subsystem: pe.subsystem,
        sectionCount: pe.sections.length
      },
      warnings
    }
  }
  const elf = parseElfHeaders(buffer)
  if (elf) {
    return {
      format: 'ELF',
      arch: elf.arch,
      bitness: elf.bitness,
      endian: elf.endian,
      subtype: elf.type,
      details: {
        machine: elf.machine,
        type: elf.type,
        osAbi: elf.osAbi,
        sectionCount: elf.sections.length
      },
      warnings
    }
  }
  const macho = parseMachOHeaders(buffer)
  if (macho) {
    return {
      format: 'Mach-O',
      arch: macho.arch,
      bitness: macho.bitness,
      endian: macho.endian,
      subtype: macho.fileType,
      details: {
        magic: macho.magic,
        cpuType: macho.cpuType,
        fileType: macho.fileType,
        commandCount: macho.commandCount
      },
      warnings
    }
  }
  if (buffer[0] === 0x50 && buffer[1] === 0x4b) {
    const entries = parseZipEntries(buffer)
    const names = entries.map((entry) => entry.name)
    const isApk = names.includes('AndroidManifest.xml') || names.some((name) => name === 'classes.dex')
    return {
      format: isApk ? 'APK' : 'ZIP',
      subtype: isApk ? 'Android package' : 'ZIP archive',
      details: {
        entryCount: entries.length,
        hasAndroidManifest: names.includes('AndroidManifest.xml'),
        dexFiles: names.filter((name) => /^classes\d*\.dex$/i.test(name)).length
      },
      warnings
    }
  }
  const printableRatio = printableAsciiRatio(buffer.subarray(0, Math.min(buffer.length, 4096)))
  if (printableRatio > 0.85) {
    return { format: 'Raw', subtype: 'mostly printable data', details: { printableRatio }, warnings }
  }
  return { format: 'Unknown', details: { printableRatio }, warnings }
}

export async function analyzeSections(file: ReResolvedFile): Promise<{
  ok: true
  file: string
  format: ReFormatResult
  sections: ReSection[]
  warnings: string[]
}> {
  const sample = await readBinarySample(file.absolutePath)
  const format = detectFormat(sample.buffer)
  const sections = sectionsForFormat(sample.buffer, format)
  const warnings = [...format.warnings]
  if (sample.truncated) warnings.push('section parsing used a truncated file sample')
  await updateSampleState(file, { format, sections })
  return {
    ok: true,
    file: normalizePath(file.relativePath),
    format,
    sections,
    warnings
  }
}

export async function analyzeEntropy(file: ReResolvedFile, windowSize = 4096): Promise<{
  ok: true
  file: string
  size: number
  truncated: boolean
  overall: number
  windowSize: number
  highestWindows: Array<{ offset: number; entropy: number }>
  sectionEntropy: Array<{ name: string; entropy: number; rawOffset?: number; rawSize?: number }>
  warnings: string[]
}> {
  const sample = await readBinarySample(file.absolutePath)
  const overall = entropy(sample.buffer)
  const highestWindows = rollingEntropy(sample.buffer, windowSize).sort((a, b) => b.entropy - a.entropy).slice(0, 12)
  const format = detectFormat(sample.buffer)
  const sections = sectionsForFormat(sample.buffer, format)
  const sectionEntropy = sections
    .filter((section) => section.rawOffset !== undefined && section.rawSize !== undefined)
    .map((section) => ({
      name: section.name,
      entropy: section.entropy ?? entropy(sliceRange(sample.buffer, section.rawOffset ?? 0, section.rawSize ?? 0)),
      ...(section.rawOffset !== undefined ? { rawOffset: section.rawOffset } : {}),
      ...(section.rawSize !== undefined ? { rawSize: section.rawSize } : {})
    }))
  const warnings = sample.truncated ? ['entropy used a truncated file sample'] : []
  await updateSampleState(file, {
    entropy: { overall, windowSize, highestWindows },
    sections
  })
  return {
    ok: true,
    file: normalizePath(file.relativePath),
    size: sample.size,
    truncated: sample.truncated,
    overall,
    windowSize,
    highestWindows,
    sectionEntropy,
    warnings
  }
}

export async function analyzeStrings(file: ReResolvedFile, options: {
  minLength?: number
  limit?: number
  include?: string
  maxBytes?: number
} = {}): Promise<{
  ok: true
  file: string
  totalExtracted: number
  returned: number
  strings: ReStringRecord[]
  interesting: ReStringRecord[]
  rawOutputPath: string
  warnings: string[]
}> {
  const minLength = clampInt(options.minLength ?? 4, 3, 256)
  const limit = clampInt(options.limit ?? DEFAULT_RETURN_LIMIT, 1, 5_000)
  const maxBytes = clampInt(options.maxBytes ?? DEFAULT_MAX_ANALYSIS_BYTES, 1024, 512 * 1024 * 1024)
  const sample = await readBinarySample(file.absolutePath, maxBytes)
  const extracted = extractStrings(sample.buffer, minLength, DEFAULT_MAX_STRINGS)
  const include = options.include?.trim().toLowerCase()
  const filtered = include
    ? extracted.filter((entry) => entry.value.toLowerCase().includes(include))
    : extracted
  const interesting = filtered.filter((entry) => (entry.tags?.length ?? 0) > 0).slice(0, limit)
  const strings = (interesting.length ? interesting : filtered).slice(0, limit)
  const rawOutputPath = await saveRawOutput(file.workspaceRoot, 'strings', file.relativePath, {
    file: normalizePath(file.relativePath),
    minLength,
    truncated: sample.truncated,
    totalExtracted: extracted.length,
    strings: extracted
  })
  const warnings = sample.truncated ? ['strings extraction used a truncated file sample'] : []
  await updateSampleState(file, {
    toolSummaries: {
      strings: {
        totalExtracted: extracted.length,
        interestingReturned: interesting.length,
        rawOutputPath
      }
    }
  })
  return {
    ok: true,
    file: normalizePath(file.relativePath),
    totalExtracted: extracted.length,
    returned: strings.length,
    strings,
    interesting,
    rawOutputPath,
    warnings
  }
}

export async function analyzeImports(file: ReResolvedFile): Promise<{
  ok: true
  file: string
  format: ReFormatResult
  imports: ReImport[]
  warnings: string[]
}> {
  const sample = await readBinarySample(file.absolutePath)
  const format = detectFormat(sample.buffer)
  const warnings = [...format.warnings]
  let imports: ReImport[] = []
  if (format.format === 'PE') {
    imports = parsePeImports(sample.buffer)
  } else if (format.format === 'ELF') {
    imports = parseElfImports(sample.buffer)
  } else {
    warnings.push(`native import parsing is not implemented for ${format.format}`)
  }
  if (sample.truncated) warnings.push('import parsing used a truncated file sample')
  await updateSampleState(file, { format, imports })
  return { ok: true, file: normalizePath(file.relativePath), format, imports, warnings }
}

export async function analyzeExports(file: ReResolvedFile): Promise<{
  ok: true
  file: string
  format: ReFormatResult
  exports: ReExport[]
  warnings: string[]
}> {
  const sample = await readBinarySample(file.absolutePath)
  const format = detectFormat(sample.buffer)
  const warnings = [...format.warnings]
  let exports: ReExport[] = []
  if (format.format === 'PE') {
    exports = parsePeExports(sample.buffer)
  } else if (format.format === 'ELF') {
    exports = parseElfExports(sample.buffer)
  } else {
    warnings.push(`native export parsing is not implemented for ${format.format}`)
  }
  if (sample.truncated) warnings.push('export parsing used a truncated file sample')
  await updateSampleState(file, { format, exports })
  return { ok: true, file: normalizePath(file.relativePath), format, exports, warnings }
}

export async function analyzeIocs(file: ReResolvedFile): Promise<{
  ok: true
  file: string
  iocs: ReIocs
  counts: Record<keyof ReIocs, number>
  rawOutputPath: string
  warnings: string[]
}> {
  const strings = await analyzeStrings(file, { minLength: 4, limit: 500 })
  const rawStringsOutput = strings.strings.length >= strings.totalExtracted
    ? null
    : await readJson(join(file.workspaceRoot, strings.rawOutputPath)).catch(() => null)
  const values = strings.strings.length >= strings.totalExtracted
    ? strings.strings
    : Array.isArray((rawStringsOutput as { strings?: unknown } | null)?.strings)
      ? (rawStringsOutput as { strings: ReStringRecord[] }).strings
      : strings.strings
  const imports = await analyzeImports(file).catch(() => ({ imports: [] as ReImport[] }))
  const iocs = extractIocs(values, imports.imports)
  const paths = await ensureReWorkspace(file.workspaceRoot)
  await writeJson(paths.iocs, iocs)
  const rawOutputPath = await saveRawOutput(file.workspaceRoot, 'iocs', file.relativePath, iocs)
  await updateSampleState(file, { iocs })
  return {
    ok: true,
    file: normalizePath(file.relativePath),
    iocs,
    counts: iocCounts(iocs),
    rawOutputPath,
    warnings: strings.warnings
  }
}

export async function analyzeCapabilities(file: ReResolvedFile): Promise<{
  ok: true
  file: string
  capabilities: ReCapability[]
  warnings: string[]
}> {
  const [importsResult, stringsResult] = await Promise.all([
    analyzeImports(file).catch((error: unknown) => ({
      imports: [] as ReImport[],
      warnings: [errorMessage(error)]
    })),
    analyzeStrings(file, { minLength: 4, limit: 1_000 })
  ])
  const capabilities = classifyCapabilities(importsResult.imports, stringsResult.strings)
  const warnings = [...(importsResult.warnings ?? []), ...stringsResult.warnings]
  await updateSampleState(file, { capabilities })
  return { ok: true, file: normalizePath(file.relativePath), capabilities, warnings }
}

export async function analyzePacker(file: ReResolvedFile): Promise<{
  ok: true
  file: string
  indicators: Array<{ indicator: string; confidence: 'low' | 'medium' | 'high'; evidence: string[] }>
  warnings: string[]
}> {
  const [sectionsResult, entropyResult, importsResult, stringsResult] = await Promise.all([
    analyzeSections(file),
    analyzeEntropy(file),
    analyzeImports(file).catch(() => ({ imports: [] as ReImport[], warnings: [] as string[] })),
    analyzeStrings(file, { minLength: 4, limit: 500 })
  ])
  const indicators = detectPackerIndicators({
    sections: sectionsResult.sections,
    imports: importsResult.imports,
    strings: stringsResult.strings,
    entropy: entropyResult.overall
  })
  await updateSampleState(file, { packerIndicators: indicators })
  return {
    ok: true,
    file: normalizePath(file.relativePath),
    indicators,
    warnings: [...sectionsResult.warnings, ...entropyResult.warnings, ...(importsResult.warnings ?? []), ...stringsResult.warnings]
  }
}

export async function analyzeCrypto(file: ReResolvedFile): Promise<{
  ok: true
  file: string
  summary: string
  imports: string[]
  constants: Array<{ name: string; offset?: number; evidence: string }>
  highEntropyData: Array<{ offset: number; entropy: number }>
  candidateStrings: ReStringRecord[]
  candidateFunctions: Array<{ name: string; evidence: string[]; confidence: 'low' | 'medium' | 'high' }>
  recommendedNextSteps: string[]
  warnings: string[]
}> {
  const [sample, importsResult, stringsResult, entropyResult] = await Promise.all([
    readBinarySample(file.absolutePath),
    analyzeImports(file).catch(() => ({ imports: [] as ReImport[], warnings: [] as string[] })),
    analyzeStrings(file, { minLength: 4, limit: 1_000 }),
    analyzeEntropy(file)
  ])
  const importNames = importsResult.imports.flatMap((entry) => entry.symbols.map((symbol) => `${entry.library}!${symbol}`))
  const cryptoImports = importNames.filter((name) => CRYPTO_PATTERN.test(name)).slice(0, 200)
  const constants = findCryptoConstants(sample.buffer)
  const candidateStrings = stringsResult.strings.filter((entry) => CRYPTO_PATTERN.test(entry.value)).slice(0, 100)
  const highEntropyData = entropyResult.highestWindows.filter((entry) => entry.entropy >= 7.2).slice(0, 12)
  const candidateFunctions = cryptoImports.length || constants.length || candidateStrings.length
    ? [{
        name: 'unknown_crypto_or_encoding_routine',
        evidence: [
          ...cryptoImports.slice(0, 8),
          ...constants.slice(0, 8).map((entry) => entry.name),
          ...candidateStrings.slice(0, 8).map((entry) => entry.value)
        ],
        confidence: cryptoImports.length > 0 || constants.length > 1 ? 'medium' as const : 'low' as const
      }]
    : []
  const recommendedNextSteps = [
    ...(cryptoImports.length ? ['Inspect callers of imported crypto APIs.'] : []),
    ...(constants.length ? ['Search xrefs to crypto constant offsets in a disassembler.'] : []),
    ...(highEntropyData.length ? ['Inspect high-entropy data for encrypted config or compressed payloads.'] : []),
    'Run capa/rizin/Ghidra if available for function-level confirmation.'
  ]
  const result = {
    ok: true as const,
    file: normalizePath(file.relativePath),
    summary: cryptoImports.length || constants.length || candidateStrings.length || highEntropyData.length
      ? 'Crypto, encoding, compression, or encrypted-data candidates were found.'
      : 'No strong crypto or encoding candidates were found from static MVP heuristics.',
    imports: cryptoImports,
    constants,
    highEntropyData,
    candidateStrings,
    candidateFunctions,
    recommendedNextSteps,
    warnings: [...(importsResult.warnings ?? []), ...stringsResult.warnings, ...entropyResult.warnings]
  }
  await updateSampleState(file, { cryptoCandidates: result })
  return result
}

export async function triageBinary(file: ReResolvedFile): Promise<{
  ok: true
  file: string
  executiveSummary: string
  fileInfo: Awaited<ReturnType<typeof analyzeFileInfo>>
  sections: ReSection[]
  imports: ReImport[]
  exports: ReExport[]
  stringsOfInterest: ReStringRecord[]
  iocs: ReIocs
  entropy: Awaited<ReturnType<typeof analyzeEntropy>>
  packerIndicators: Array<{ indicator: string; confidence: 'low' | 'medium' | 'high'; evidence: string[] }>
  capabilities: ReCapability[]
  recommendedInspectionTargets: string[]
  rawOutputPath: string
  warnings: string[]
}> {
  const fileInfo = await analyzeFileInfo(file)
  const [sectionsResult, importsResult, exportsResult, stringsResult, iocResult, entropyResult, packerResult, capabilityResult] =
    await Promise.all([
      analyzeSections(file),
      analyzeImports(file),
      analyzeExports(file),
      analyzeStrings(file, { minLength: 4, limit: 120 }),
      analyzeIocs(file),
      analyzeEntropy(file),
      analyzePacker(file),
      analyzeCapabilities(file)
    ])
  const recommendedInspectionTargets = recommendTargets({
    sections: sectionsResult.sections,
    imports: importsResult.imports,
    strings: stringsResult.interesting,
    capabilities: capabilityResult.capabilities,
    iocs: iocResult.iocs,
    packerIndicators: packerResult.indicators
  })
  await updateSampleState(file, { recommendedTargets: recommendedInspectionTargets })
  const executiveSummary = buildTriageSummary({
    fileInfo,
    imports: importsResult.imports,
    iocs: iocResult.iocs,
    capabilities: capabilityResult.capabilities,
    packerIndicators: packerResult.indicators
  })
  const warnings = [
    ...fileInfo.warnings,
    ...sectionsResult.warnings,
    ...importsResult.warnings,
    ...exportsResult.warnings,
    ...stringsResult.warnings,
    ...iocResult.warnings,
    ...entropyResult.warnings,
    ...packerResult.warnings,
    ...capabilityResult.warnings
  ].filter(Boolean)
  const rawOutputPath = await saveRawOutput(file.workspaceRoot, 'triage', file.relativePath, {
    fileInfo,
    sections: sectionsResult.sections,
    imports: importsResult.imports,
    exports: exportsResult.exports,
    strings: stringsResult.strings,
    iocs: iocResult.iocs,
    entropy: entropyResult,
    packerIndicators: packerResult.indicators,
    capabilities: capabilityResult.capabilities,
    recommendedInspectionTargets,
    warnings
  })
  return {
    ok: true,
    file: normalizePath(file.relativePath),
    executiveSummary,
    fileInfo,
    sections: sectionsResult.sections,
    imports: importsResult.imports,
    exports: exportsResult.exports,
    stringsOfInterest: stringsResult.interesting,
    iocs: iocResult.iocs,
    entropy: entropyResult,
    packerIndicators: packerResult.indicators,
    capabilities: capabilityResult.capabilities,
    recommendedInspectionTargets,
    rawOutputPath,
    warnings
  }
}

export async function compareBinaries(fileA: ReResolvedFile, fileB: ReResolvedFile): Promise<{
  ok: true
  fileA: string
  fileB: string
  hashes: { a: ReHashResult; b: ReHashResult; same: boolean }
  formatChanges: Record<string, unknown>
  sectionChanges: { added: string[]; removed: string[]; changed: string[] }
  importChanges: { added: string[]; removed: string[] }
  exportChanges: { added: string[]; removed: string[] }
  stringChanges: { added: string[]; removed: string[] }
  interestingDeltas: string[]
  recommendedReviewTargets: string[]
  rawOutputPath: string
}> {
  const [hashA, hashB, sampleA, sampleB] = await Promise.all([
    hashFile(fileA.absolutePath),
    hashFile(fileB.absolutePath),
    readBinarySample(fileA.absolutePath),
    readBinarySample(fileB.absolutePath)
  ])
  const formatA = detectFormat(sampleA.buffer)
  const formatB = detectFormat(sampleB.buffer)
  const sectionsA = sectionsForFormat(sampleA.buffer, formatA)
  const sectionsB = sectionsForFormat(sampleB.buffer, formatB)
  const importsA = await analyzeImports(fileA).catch(() => ({ imports: [] as ReImport[] }))
  const importsB = await analyzeImports(fileB).catch(() => ({ imports: [] as ReImport[] }))
  const exportsA = await analyzeExports(fileA).catch(() => ({ exports: [] as ReExport[] }))
  const exportsB = await analyzeExports(fileB).catch(() => ({ exports: [] as ReExport[] }))
  const stringsA = extractStrings(sampleA.buffer, 4, 20_000).map((entry) => entry.value)
  const stringsB = extractStrings(sampleB.buffer, 4, 20_000).map((entry) => entry.value)
  const sectionChanges = diffNamed(
    sectionsA.map((section) => `${section.name}:${section.rawSize ?? 0}:${section.virtualSize ?? 0}:${section.characteristics ?? ''}`),
    sectionsB.map((section) => `${section.name}:${section.rawSize ?? 0}:${section.virtualSize ?? 0}:${section.characteristics ?? ''}`)
  )
  const importChanges = diffSets(flattenImports(importsA.imports), flattenImports(importsB.imports), 200)
  const exportChanges = diffSets(exportsA.exports.map((entry) => entry.name), exportsB.exports.map((entry) => entry.name), 200)
  const stringChanges = diffSets(stringsA, stringsB, 200)
  const interestingDeltas = [
    ...(hashA.sha256 === hashB.sha256 ? ['Files are byte-identical by SHA-256.'] : ['Files differ by SHA-256.']),
    ...(formatA.format !== formatB.format || formatA.arch !== formatB.arch ? ['File format or architecture changed.'] : []),
    ...(importChanges.added.length ? [`New imports: ${importChanges.added.slice(0, 8).join(', ')}`] : []),
    ...(stringChanges.added.some((value) => IOC_HINT_PATTERN.test(value)) ? ['New IOC-like strings appeared.'] : [])
  ]
  const recommendedReviewTargets = [
    ...importChanges.added.slice(0, 25),
    ...stringChanges.added.filter((value) => IOC_HINT_PATTERN.test(value)).slice(0, 25),
    ...sectionChanges.changed.slice(0, 25)
  ]
  const diff = {
    ok: true as const,
    fileA: normalizePath(fileA.relativePath),
    fileB: normalizePath(fileB.relativePath),
    hashes: { a: hashA, b: hashB, same: hashA.sha256 === hashB.sha256 },
    formatChanges: { a: formatA, b: formatB },
    sectionChanges,
    importChanges,
    exportChanges,
    stringChanges,
    interestingDeltas,
    recommendedReviewTargets
  }
  const paths = await ensureReWorkspace(fileA.workspaceRoot)
  const diffName = sanitizeFileName(`diff-${basename(fileA.relativePath)}-${basename(fileB.relativePath)}-${Date.now()}.json`)
  await writeJson(join(paths.diffs, diffName), diff)
  const rawOutputPath = normalizePath(relative(fileA.workspaceRoot, join(paths.diffs, diffName)))
  return { ...diff, rawOutputPath }
}

export async function generateReport(workspaceRoot: string, file?: ReResolvedFile): Promise<{
  ok: true
  reportPath: string
  markdown: string
  warnings: string[]
}> {
  if (file) {
    const state = await loadAnalysisState(workspaceRoot)
    const hasCurrent = state.currentSample && Object.values(state.samples).some((sample) => sample.path === file.relativePath)
    if (!hasCurrent) await triageBinary(file)
  }
  const paths = await ensureReWorkspace(workspaceRoot)
  const state = await loadAnalysisState(workspaceRoot)
  const symbols = await loadSymbolsState(workspaceRoot)
  const iocs = await readJson(paths.iocs).catch(() => EMPTY_IOCS) as ReIocs
  const behaviorGraph = await readJson(paths.behaviorGraph).catch(() => null)
  const notes = await readFile(paths.notes, 'utf8').catch(() => '')
  const sample = state.currentSample ? state.samples[state.currentSample] : Object.values(state.samples)[0]
  const markdown = renderReport({ state, sample, iocs, symbols, notes, behaviorGraph })
  await writeFile(paths.report, markdown, 'utf8')
  return {
    ok: true,
    reportPath: normalizePath(relative(workspaceRoot, paths.report)),
    markdown,
    warnings: sample ? [] : ['No current sample was found in analysis state; generated a workspace-level report.']
  }
}

export async function appendNote(workspaceRoot: string, note: string, title?: string): Promise<{ ok: true; notesPath: string }> {
  const paths = await ensureReWorkspace(workspaceRoot)
  const entry = [
    '',
    `## ${title?.trim() || `Note ${new Date().toISOString()}`}`,
    '',
    note.trim(),
    ''
  ].join('\n')
  const current = await readFile(paths.notes, 'utf8').catch(() => '# Reverse Engineering Notes\n')
  await writeFile(paths.notes, `${current.replace(/\s*$/, '')}\n${entry}`, 'utf8')
  return { ok: true, notesPath: normalizePath(relative(workspaceRoot, paths.notes)) }
}

export function toolAvailability(): {
  ok: true
  available: Array<{ tool: string; path: string; feature: string }>
  missing: Array<{ tool: string; feature: string; installHint: string }>
} {
  const tools = [
    ['file', 'basic file identification', 'Install Git for Windows, MSYS2, WSL, or coreutils.'],
    ['strings', 'external strings extraction', 'Install Sysinternals, binutils, Git for Windows, or WSL.'],
    ['objdump', 'disassembly and import/symbol fallback', 'Install binutils, LLVM, or WSL.'],
    ['readelf', 'ELF headers, symbols, and dynamic imports', 'Install binutils or WSL.'],
    ['otool', 'Mach-O headers and imports on macOS', 'Install Xcode command line tools on macOS.'],
    ['rabin2', 'radare2/rizin binary metadata', 'Install radare2 or rizin.'],
    ['rizin', 'advanced disassembly and xrefs', 'Install rizin.'],
    ['radare2', 'advanced disassembly and xrefs', 'Install radare2.'],
    ['yara', 'YARA rule scanning', 'Install YARA.'],
    ['capa', 'capability detection', 'Install Mandiant capa.'],
    ['diec', 'packer/compiler detection', 'Install Detect It Easy CLI.'],
    ['ghidra', 'decompilation and project-based function analysis', 'Install Ghidra and add it to PATH.'],
    ['apktool', 'APK resources and manifest decoding', 'Install apktool.'],
    ['jadx', 'APK Java/Kotlin decompilation', 'Install jadx.']
  ] as const
  const available: Array<{ tool: string; path: string; feature: string }> = []
  const missing: Array<{ tool: string; feature: string; installHint: string }> = []
  for (const [tool, feature, installHint] of tools) {
    const path = findExecutable(tool)
    if (path) available.push({ tool, path, feature })
    else missing.push({ tool, feature, installHint })
  }
  return { ok: true, available, missing }
}

export function extractStrings(buffer: Buffer, minLength = 4, maxStrings = DEFAULT_MAX_STRINGS): ReStringRecord[] {
  const out: ReStringRecord[] = []
  let start = -1
  for (let index = 0; index < buffer.length; index += 1) {
    if (isPrintableByte(buffer[index] ?? 0)) {
      if (start < 0) start = index
      continue
    }
    if (start >= 0 && index - start >= minLength) {
      pushString(out, { offset: start, encoding: 'ascii', value: buffer.subarray(start, index).toString('latin1') }, maxStrings)
    }
    start = -1
  }
  if (start >= 0 && buffer.length - start >= minLength) {
    pushString(out, { offset: start, encoding: 'ascii', value: buffer.subarray(start).toString('latin1') }, maxStrings)
  }

  start = -1
  let chars = ''
  for (let index = 0; index + 1 < buffer.length; index += 2) {
    const byte = buffer[index] ?? 0
    const nul = buffer[index + 1] ?? 0
    if (nul === 0 && isPrintableByte(byte)) {
      if (start < 0) start = index
      chars += String.fromCharCode(byte)
      continue
    }
    if (start >= 0 && chars.length >= minLength) {
      pushString(out, { offset: start, encoding: 'utf16le', value: chars }, maxStrings)
    }
    start = -1
    chars = ''
  }
  if (start >= 0 && chars.length >= minLength) {
    pushString(out, { offset: start, encoding: 'utf16le', value: chars }, maxStrings)
  }
  return out.sort((a, b) => a.offset - b.offset)
}

export function extractIocs(strings: ReStringRecord[], imports: ReImport[] = []): ReIocs {
  const buckets = createIocBuckets()
  const importSymbols = flattenImports(imports)
  for (const symbol of importSymbols) {
    for (const apiName of suspiciousApiNames(symbol)) addIoc(buckets.suspiciousApis, apiName)
    if (CRYPTO_PATTERN.test(symbol)) addIoc(buckets.cryptoConstants, symbol)
  }
  for (const entry of strings) {
    const value = entry.value.trim()
    if (!value) continue
    for (const match of value.matchAll(URL_PATTERN)) addIoc(buckets.urls, trimPunctuation(match[0]))
    for (const match of value.matchAll(EMAIL_PATTERN)) addIoc(buckets.emails, trimPunctuation(match[0]))
    for (const match of value.matchAll(IPV4_PATTERN)) {
      const candidate = match[0]
      if (isValidIpv4(candidate)) addIoc(buckets.ipv4, candidate)
    }
    for (const match of value.matchAll(IPV6_PATTERN)) addIoc(buckets.ipv6, trimPunctuation(match[0]))
    for (const match of value.matchAll(DOMAIN_PATTERN)) {
      const domain = trimPunctuation(match[0]).toLowerCase()
      if (!looksLikeFileName(domain)) addIoc(buckets.domains, domain)
    }
    for (const match of value.matchAll(REGISTRY_PATTERN)) addIoc(buckets.registryKeys, trimPunctuation(match[0]))
    for (const match of value.matchAll(WINDOWS_PATH_PATTERN)) addIoc(buckets.windowsPaths, trimPunctuation(match[0]))
    for (const match of value.matchAll(UNIX_PATH_PATTERN)) addIoc(buckets.unixPaths, trimPunctuation(match[1] ?? match[0]))
    if (USER_AGENT_PATTERN.test(value)) addIoc(buckets.userAgents, value)
    if (POWERSHELL_PATTERN.test(value)) addIoc(buckets.powershellCommands, value)
    if (SHELL_COMMAND_PATTERN.test(value)) addIoc(buckets.shellCommands, value)
    if (BASE64_PATTERN.test(value) && value.length % 4 === 0) addIoc(buckets.base64Blobs, value)
    if (HEX_BLOB_PATTERN.test(value)) addIoc(buckets.hexBlobs, value)
    if (MUTEX_PATTERN.test(value)) addIoc(buckets.mutexes, value)
    if (CRYPTO_PATTERN.test(value)) addIoc(buckets.cryptoConstants, value)
    for (const apiName of suspiciousApiNames(value)) addIoc(buckets.suspiciousApis, apiName)
    const maybeFile = maybeFileName(value)
    if (maybeFile) addIoc(buckets.fileNames, maybeFile)
  }
  return sortIocs(buckets)
}

export function entropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0
  const counts = new Array<number>(256).fill(0)
  for (const byte of buffer) counts[byte] += 1
  let value = 0
  for (const count of counts) {
    if (count === 0) continue
    const p = count / buffer.length
    value -= p * Math.log2(p)
  }
  return round(value, 3)
}

function sectionsForFormat(buffer: Buffer, format: ReFormatResult): ReSection[] {
  if (format.format === 'PE') return parsePeHeaders(buffer)?.sections ?? []
  if (format.format === 'ELF') return parseElfHeaders(buffer)?.sections ?? []
  if (format.format === 'Mach-O') return parseMachOHeaders(buffer)?.sections ?? []
  if (format.format === 'APK' || format.format === 'ZIP') {
    return parseZipEntries(buffer).map((entry) => ({
      name: entry.name,
      type: 'zip-entry',
      rawOffset: entry.localHeaderOffset,
      rawSize: entry.compressedSize,
      virtualSize: entry.uncompressedSize,
      flags: [entry.compressionMethod === 0 ? 'stored' : `compression:${entry.compressionMethod}`]
    }))
  }
  return []
}

type PeHeaders = {
  machineHex: string
  arch: string
  bitness: 32 | 64
  timestamp: string
  imageBase: number
  entryPointRva: number
  subsystem: string
  importDirectoryRva: number
  exportDirectoryRva: number
  sections: ReSection[]
}

function parsePeHeaders(buffer: Buffer): PeHeaders | null {
  if (buffer.length < 0x40 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) return null
  const peOffset = readUInt32LE(buffer, 0x3c)
  if (peOffset == null || peOffset + 0x18 >= buffer.length) return null
  if (buffer.toString('ascii', peOffset, peOffset + 4) !== 'PE\u0000\u0000') return null
  const machine = readUInt16LE(buffer, peOffset + 4) ?? 0
  const sectionCount = readUInt16LE(buffer, peOffset + 6) ?? 0
  const timestampRaw = readUInt32LE(buffer, peOffset + 8) ?? 0
  const optionalSize = readUInt16LE(buffer, peOffset + 20) ?? 0
  const optionalOffset = peOffset + 24
  const magic = readUInt16LE(buffer, optionalOffset) ?? 0
  const bitness: 32 | 64 = magic === 0x20b ? 64 : 32
  const entryPointRva = readUInt32LE(buffer, optionalOffset + 16) ?? 0
  const imageBase = bitness === 64
    ? Number(readBigUInt64LE(buffer, optionalOffset + 24) ?? 0n)
    : readUInt32LE(buffer, optionalOffset + 28) ?? 0
  const subsystemValue = readUInt16LE(buffer, optionalOffset + (bitness === 64 ? 0x5c : 0x44)) ?? 0
  const directoryOffset = optionalOffset + (bitness === 64 ? 112 : 96)
  const exportDirectoryRva = readUInt32LE(buffer, directoryOffset) ?? 0
  const importDirectoryRva = readUInt32LE(buffer, directoryOffset + 8) ?? 0
  const sectionOffset = optionalOffset + optionalSize
  const sections: ReSection[] = []
  for (let index = 0; index < sectionCount; index += 1) {
    const offset = sectionOffset + index * 40
    if (offset + 40 > buffer.length) break
    const name = readFixedAscii(buffer, offset, 8) || `.sec${index}`
    const virtualSize = readUInt32LE(buffer, offset + 8) ?? 0
    const virtualAddress = readUInt32LE(buffer, offset + 12) ?? 0
    const rawSize = readUInt32LE(buffer, offset + 16) ?? 0
    const rawOffset = readUInt32LE(buffer, offset + 20) ?? 0
    const characteristicsValue = readUInt32LE(buffer, offset + 36) ?? 0
    const raw = sliceRange(buffer, rawOffset, rawSize)
    sections.push({
      name,
      type: 'section',
      virtualAddress: hex(virtualAddress),
      virtualSize,
      rawOffset,
      rawSize,
      entropy: entropy(raw),
      flags: peSectionFlags(characteristicsValue),
      characteristics: hex(characteristicsValue)
    })
  }
  return {
    machineHex: hex(machine),
    arch: peMachineArch(machine),
    bitness,
    timestamp: timestampRaw > 0 ? new Date(timestampRaw * 1000).toISOString() : '',
    imageBase,
    entryPointRva,
    subsystem: peSubsystemName(subsystemValue),
    importDirectoryRva,
    exportDirectoryRva,
    sections
  }
}

function parsePeImports(buffer: Buffer): ReImport[] {
  const pe = parsePeHeaders(buffer)
  if (!pe || !pe.importDirectoryRva) return []
  const importOffset = rvaToOffset(pe.importDirectoryRva, pe.sections)
  if (importOffset == null) return []
  const out: ReImport[] = []
  for (let desc = importOffset; desc + 20 <= buffer.length; desc += 20) {
    const originalFirstThunk = readUInt32LE(buffer, desc) ?? 0
    const nameRva = readUInt32LE(buffer, desc + 12) ?? 0
    const firstThunk = readUInt32LE(buffer, desc + 16) ?? 0
    if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break
    const nameOffset = rvaToOffset(nameRva, pe.sections)
    const library = nameOffset == null ? `dll_${out.length}` : readCString(buffer, nameOffset, 260)
    const thunkRva = originalFirstThunk || firstThunk
    const thunkOffset = rvaToOffset(thunkRva, pe.sections)
    const symbols: string[] = []
    if (thunkOffset != null) {
      const thunkSize = pe.bitness === 64 ? 8 : 4
      for (let offset = thunkOffset; offset + thunkSize <= buffer.length && symbols.length < 4096; offset += thunkSize) {
        const raw = pe.bitness === 64
          ? readBigUInt64LE(buffer, offset) ?? 0n
          : BigInt(readUInt32LE(buffer, offset) ?? 0)
        if (raw === 0n) break
        const ordinalFlag = pe.bitness === 64 ? 0x8000000000000000n : 0x80000000n
        if ((raw & ordinalFlag) !== 0n) {
          symbols.push(`ordinal_${Number(raw & 0xffffn)}`)
          continue
        }
        const importByNameOffset = rvaToOffset(Number(raw), pe.sections)
        if (importByNameOffset == null || importByNameOffset + 2 >= buffer.length) continue
        const symbol = readCString(buffer, importByNameOffset + 2, 512)
        if (symbol) symbols.push(symbol)
      }
    }
    out.push({ library: library || `dll_${out.length}`, symbols: uniqueSorted(symbols) })
  }
  return out
}

function parsePeExports(buffer: Buffer): ReExport[] {
  const pe = parsePeHeaders(buffer)
  if (!pe || !pe.exportDirectoryRva) return []
  const exportOffset = rvaToOffset(pe.exportDirectoryRva, pe.sections)
  if (exportOffset == null || exportOffset + 40 > buffer.length) return []
  const base = readUInt32LE(buffer, exportOffset + 16) ?? 0
  const numberOfFunctions = readUInt32LE(buffer, exportOffset + 20) ?? 0
  const numberOfNames = readUInt32LE(buffer, exportOffset + 24) ?? 0
  const functionsOffset = rvaToOffset(readUInt32LE(buffer, exportOffset + 28) ?? 0, pe.sections)
  const namesOffset = rvaToOffset(readUInt32LE(buffer, exportOffset + 32) ?? 0, pe.sections)
  const ordinalsOffset = rvaToOffset(readUInt32LE(buffer, exportOffset + 36) ?? 0, pe.sections)
  if (functionsOffset == null || namesOffset == null || ordinalsOffset == null) return []
  const out: ReExport[] = []
  for (let index = 0; index < numberOfNames && index < 8192; index += 1) {
    const nameRva = readUInt32LE(buffer, namesOffset + index * 4) ?? 0
    const nameOffset = rvaToOffset(nameRva, pe.sections)
    const ordinalIndex = readUInt16LE(buffer, ordinalsOffset + index * 2) ?? 0
    const functionRva = ordinalIndex < numberOfFunctions
      ? readUInt32LE(buffer, functionsOffset + ordinalIndex * 4) ?? 0
      : 0
    if (nameOffset == null) continue
    out.push({
      name: readCString(buffer, nameOffset, 512),
      address: hex(pe.imageBase + functionRva),
      ordinal: base + ordinalIndex
    })
  }
  return out.filter((entry) => entry.name)
}

type ElfHeaders = {
  arch: string
  bitness: 32 | 64
  endian: 'little' | 'big'
  machine: string
  type: string
  osAbi: string
  sections: ReSection[]
  symbols: Array<{ name: string; imported: boolean; exported: boolean; type: string; value: string }>
}

function parseElfHeaders(buffer: Buffer): ElfHeaders | null {
  if (buffer.length < 0x40 || buffer[0] !== 0x7f || buffer.toString('ascii', 1, 4) !== 'ELF') return null
  const bitness: 32 | 64 = buffer[4] === 2 ? 64 : 32
  const endian: 'little' | 'big' = buffer[5] === 2 ? 'big' : 'little'
  const read16 = (offset: number) => readUInt16(buffer, offset, endian) ?? 0
  const read32 = (offset: number) => readUInt32(buffer, offset, endian) ?? 0
  const read64 = (offset: number) => Number(readBigUInt64(buffer, offset, endian) ?? 0n)
  const typeValue = read16(16)
  const machineValue = read16(18)
  const osAbiValue = buffer[7] ?? 0
  const shoff = bitness === 64 ? read64(40) : read32(32)
  const shentsize = bitness === 64 ? read16(58) : read16(46)
  const shnum = bitness === 64 ? read16(60) : read16(48)
  const shstrndx = bitness === 64 ? read16(62) : read16(50)
  const rawSections: Array<{
    nameOffset: number
    name: string
    type: number
    flags: number
    addr: number
    offset: number
    size: number
    link: number
    entsize: number
  }> = []
  for (let index = 0; shoff > 0 && index < shnum; index += 1) {
    const offset = shoff + index * shentsize
    if (offset + shentsize > buffer.length) break
    if (bitness === 64) {
      rawSections.push({
        nameOffset: read32(offset),
        name: '',
        type: read32(offset + 4),
        flags: Number(readBigUInt64(buffer, offset + 8, endian) ?? 0n),
        addr: read64(offset + 16),
        offset: read64(offset + 24),
        size: read64(offset + 32),
        link: read32(offset + 40),
        entsize: read64(offset + 56)
      })
    } else {
      rawSections.push({
        nameOffset: read32(offset),
        name: '',
        type: read32(offset + 4),
        flags: read32(offset + 8),
        addr: read32(offset + 12),
        offset: read32(offset + 16),
        size: read32(offset + 20),
        link: read32(offset + 24),
        entsize: read32(offset + 36)
      })
    }
  }
  const shstr = rawSections[shstrndx]
  for (const section of rawSections) {
    section.name = shstr ? readCString(buffer, shstr.offset + section.nameOffset, 512) : ''
  }
  const sections = rawSections.map((section, index): ReSection => ({
    name: section.name || `section_${index}`,
    type: elfSectionType(section.type),
    virtualAddress: hex(section.addr),
    virtualSize: section.size,
    rawOffset: section.offset,
    rawSize: section.size,
    entropy: entropy(sliceRange(buffer, section.offset, section.size)),
    flags: elfSectionFlags(section.flags)
  }))
  const symbols = parseElfSymbols(buffer, rawSections, bitness, endian)
  return {
    arch: elfMachineArch(machineValue),
    bitness,
    endian,
    machine: elfMachineArch(machineValue),
    type: elfTypeName(typeValue),
    osAbi: elfOsAbi(osAbiValue),
    sections,
    symbols
  }
}

function parseElfSymbols(
  buffer: Buffer,
  sections: Array<{ name: string; type: number; offset: number; size: number; link: number; entsize: number }>,
  bitness: 32 | 64,
  endian: 'little' | 'big'
): ElfHeaders['symbols'] {
  const read16 = (offset: number) => readUInt16(buffer, offset, endian) ?? 0
  const read32 = (offset: number) => readUInt32(buffer, offset, endian) ?? 0
  const read64 = (offset: number) => Number(readBigUInt64(buffer, offset, endian) ?? 0n)
  const out: ElfHeaders['symbols'] = []
  for (const section of sections) {
    if (section.type !== 2 && section.type !== 11) continue
    const strtab = sections[section.link]
    if (!strtab) continue
    const entrySize = section.entsize || (bitness === 64 ? 24 : 16)
    const count = Math.min(Math.floor(section.size / entrySize), 65_536)
    for (let index = 0; index < count; index += 1) {
      const offset = section.offset + index * entrySize
      if (offset + entrySize > buffer.length) break
      const nameOffset = read32(offset)
      let info = 0
      let shndx = 0
      let value = 0
      if (bitness === 64) {
        info = buffer[offset + 4] ?? 0
        shndx = read16(offset + 6)
        value = read64(offset + 8)
      } else {
        value = read32(offset + 4)
        info = buffer[offset + 12] ?? 0
        shndx = read16(offset + 14)
      }
      const name = readCString(buffer, strtab.offset + nameOffset, 1024)
      if (!name) continue
      const bind = info >> 4
      const symType = info & 0xf
      const exported = shndx !== 0 && (bind === 1 || bind === 2)
      const imported = shndx === 0 && (bind === 1 || bind === 2)
      out.push({ name, imported, exported, type: elfSymbolType(symType), value: hex(value) })
    }
  }
  return out
}

function parseElfImports(buffer: Buffer): ReImport[] {
  const elf = parseElfHeaders(buffer)
  if (!elf) return []
  const symbols = uniqueSorted(elf.symbols.filter((symbol) => symbol.imported).map((symbol) => symbol.name))
  return symbols.length ? [{ library: 'ELF dynamic symbols', symbols }] : []
}

function parseElfExports(buffer: Buffer): ReExport[] {
  const elf = parseElfHeaders(buffer)
  if (!elf) return []
  return elf.symbols
    .filter((symbol) => symbol.exported)
    .slice(0, 10_000)
    .map((symbol) => ({ name: symbol.name, address: symbol.value }))
}

type MachOHeaders = {
  magic: string
  arch: string
  bitness: 32 | 64
  endian: 'little' | 'big'
  cpuType: string
  fileType: string
  commandCount: number
  sections: ReSection[]
}

function parseMachOHeaders(buffer: Buffer): MachOHeaders | null {
  const magicLe = readUInt32LE(buffer, 0)
  const magicBe = readUInt32BE(buffer, 0)
  const known = new Set([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca])
  if (!known.has(magicLe ?? 0) && !known.has(magicBe ?? 0)) return null
  if (magicBe === 0xcafebabe || magicLe === 0xbebafeca) {
    return {
      magic: 'fat',
      arch: 'universal',
      bitness: 64,
      endian: 'big',
      cpuType: 'multiple',
      fileType: 'fat',
      commandCount: readUInt32BE(buffer, 4) ?? 0,
      sections: []
    }
  }
  const endian: 'little' | 'big' = magicLe === 0xfeedface || magicLe === 0xfeedfacf ? 'little' : 'big'
  const bitness: 32 | 64 = magicLe === 0xfeedfacf || magicBe === 0xcffaedfe ? 64 : 32
  const read32 = (offset: number) => readUInt32(buffer, offset, endian) ?? 0
  const cpu = read32(4)
  const fileTypeValue = read32(12)
  const commandCount = read32(16)
  let commandOffset = bitness === 64 ? 32 : 28
  const sections: ReSection[] = []
  for (let commandIndex = 0; commandIndex < commandCount && commandOffset + 8 <= buffer.length; commandIndex += 1) {
    const cmd = read32(commandOffset)
    const cmdSize = read32(commandOffset + 4)
    if (cmdSize <= 0 || commandOffset + cmdSize > buffer.length) break
    if (cmd === 0x19 && bitness === 64) {
      const segmentName = readFixedAscii(buffer, commandOffset + 8, 16)
      const vmaddr = Number(readBigUInt64(buffer, commandOffset + 24, endian) ?? 0n)
      const fileoff = Number(readBigUInt64(buffer, commandOffset + 40, endian) ?? 0n)
      const filesize = Number(readBigUInt64(buffer, commandOffset + 48, endian) ?? 0n)
      const nsects = read32(commandOffset + 64)
      let sectionOffset = commandOffset + 72
      sections.push({
        name: segmentName,
        type: 'segment',
        virtualAddress: hex(vmaddr),
        rawOffset: fileoff,
        rawSize: filesize,
        entropy: entropy(sliceRange(buffer, fileoff, filesize))
      })
      for (let index = 0; index < nsects && sectionOffset + 80 <= commandOffset + cmdSize; index += 1) {
        const sectionName = readFixedAscii(buffer, sectionOffset, 16)
        const secSegment = readFixedAscii(buffer, sectionOffset + 16, 16)
        const addr = Number(readBigUInt64(buffer, sectionOffset + 32, endian) ?? 0n)
        const size = Number(readBigUInt64(buffer, sectionOffset + 40, endian) ?? 0n)
        const offset = read32(sectionOffset + 48)
        sections.push({
          name: `${secSegment},${sectionName}`,
          type: 'section',
          virtualAddress: hex(addr),
          rawOffset: offset,
          rawSize: size,
          entropy: entropy(sliceRange(buffer, offset, size))
        })
        sectionOffset += 80
      }
    } else if (cmd === 0x1 && bitness === 32) {
      const segmentName = readFixedAscii(buffer, commandOffset + 8, 16)
      const vmaddr = read32(commandOffset + 24)
      const fileoff = read32(commandOffset + 32)
      const filesize = read32(commandOffset + 36)
      const nsects = read32(commandOffset + 48)
      let sectionOffset = commandOffset + 56
      sections.push({
        name: segmentName,
        type: 'segment',
        virtualAddress: hex(vmaddr),
        rawOffset: fileoff,
        rawSize: filesize,
        entropy: entropy(sliceRange(buffer, fileoff, filesize))
      })
      for (let index = 0; index < nsects && sectionOffset + 68 <= commandOffset + cmdSize; index += 1) {
        const sectionName = readFixedAscii(buffer, sectionOffset, 16)
        const secSegment = readFixedAscii(buffer, sectionOffset + 16, 16)
        const addr = read32(sectionOffset + 32)
        const size = read32(sectionOffset + 36)
        const offset = read32(sectionOffset + 40)
        sections.push({
          name: `${secSegment},${sectionName}`,
          type: 'section',
          virtualAddress: hex(addr),
          rawOffset: offset,
          rawSize: size,
          entropy: entropy(sliceRange(buffer, offset, size))
        })
        sectionOffset += 68
      }
    }
    commandOffset += cmdSize
  }
  return {
    magic: bitness === 64 ? 'MH_MAGIC_64' : 'MH_MAGIC',
    arch: machoCpuArch(cpu),
    bitness,
    endian,
    cpuType: machoCpuArch(cpu),
    fileType: machoFileType(fileTypeValue),
    commandCount,
    sections
  }
}

function parseZipEntries(buffer: Buffer): Array<{
  name: string
  compressionMethod: number
  compressedSize: number
  uncompressedSize: number
  localHeaderOffset: number
}> {
  const eocd = findEndOfCentralDirectory(buffer)
  if (eocd == null) return []
  const entries = readUInt16LE(buffer, eocd + 10) ?? 0
  let offset = readUInt32LE(buffer, eocd + 16) ?? 0
  const out = []
  for (let index = 0; index < entries && offset + 46 <= buffer.length; index += 1) {
    if (readUInt32LE(buffer, offset) !== 0x02014b50) break
    const compressionMethod = readUInt16LE(buffer, offset + 10) ?? 0
    const compressedSize = readUInt32LE(buffer, offset + 20) ?? 0
    const uncompressedSize = readUInt32LE(buffer, offset + 24) ?? 0
    const fileNameLength = readUInt16LE(buffer, offset + 28) ?? 0
    const extraLength = readUInt16LE(buffer, offset + 30) ?? 0
    const commentLength = readUInt16LE(buffer, offset + 32) ?? 0
    const localHeaderOffset = readUInt32LE(buffer, offset + 42) ?? 0
    const name = buffer.toString('utf8', offset + 46, offset + 46 + fileNameLength)
    out.push({ name, compressionMethod, compressedSize, uncompressedSize, localHeaderOffset })
    offset += 46 + fileNameLength + extraLength + commentLength
  }
  return out
}

function classifyCapabilities(imports: ReImport[], strings: ReStringRecord[]): ReCapability[] {
  const haystack = [
    ...flattenImports(imports),
    ...strings.map((entry) => entry.value)
  ]
  const categories: Record<string, RegExp[]> = {
    'file system': [/CreateFile/i, /WriteFile/i, /DeleteFile/i, /FindFirstFile/i, /GetTempPath/i, /CopyFile/i],
    registry: [/Reg(Open|Set|Create|Delete|Query)/i, /HKEY_|HKLM|HKCU/i],
    network: [/Internet(Open|Connect|Read|Write)|Http(Send|Open)|WinHttp|WSAStartup|socket|connect|recv|send|URLDownloadToFile|https?:\/\//i],
    'process injection': [/VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection|QueueUserAPC|SetWindowsHookEx/i],
    'service creation': [/CreateService|OpenSCManager|StartService|ChangeServiceConfig/i],
    'scheduled tasks': [/schtasks|ITaskService|Schedule\.Service/i],
    persistence: [/Run\\|RunOnce\\|Startup|CreateService|schtasks|CurrentVersion\\Run/i],
    crypto: [/Crypt|BCrypt|NCrypt|OpenSSL|mbedTLS|libsodium|AES|RC4|SHA|MD5|RSA/i],
    compression: [/zlib|inflate|deflate|gzip|LZMA|RtlDecompressBuffer|uncompress/i],
    'anti-debug': [/IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString|BeingDebugged/i],
    'anti-VM': [/vmware|virtualbox|vbox|qemu|sandbox|wine_get_unix_file_name/i],
    privilege: [/AdjustTokenPrivileges|SeDebugPrivilege|OpenProcessToken|LookupPrivilegeValue/i],
    credential: [/CredEnumerate|CryptUnprotectData|Vault|Login Data|Cookies|password|credential/i],
    keylogging: [/GetAsyncKeyState|GetKeyState|SetWindowsHookEx|keybd_event/i],
    'screen capture': [/BitBlt|PrintWindow|GetDC|CreateCompatibleBitmap|GetDesktopWindow/i],
    clipboard: [/OpenClipboard|GetClipboardData|SetClipboardData/i],
    'browser data access': [/Chrome\\User Data|Firefox\\Profiles|Login Data|Cookies|History/i],
    'system reconnaissance': [/GetComputerName|GetUserName|EnumProcesses|CreateToolhelp32Snapshot|WMI|Win32_/i],
    'command execution': [/CreateProcess|ShellExecute|WinExec|cmd\.exe|powershell|\/bin\/sh|\/bin\/bash/i]
  }
  const out: ReCapability[] = []
  for (const [capability, patterns] of Object.entries(categories)) {
    const evidence = uniqueSorted(haystack.filter((item) => patterns.some((pattern) => pattern.test(item)))).slice(0, 30)
    if (!evidence.length) continue
    const importEvidence = evidence.filter((item) => item.includes('!')).length
    out.push({
      capability,
      confidence: importEvidence >= 2 || evidence.length >= 4 ? 'high' : importEvidence >= 1 || evidence.length >= 2 ? 'medium' : 'low',
      evidence
    })
  }
  return out.sort((a, b) => confidenceRank(b.confidence) - confidenceRank(a.confidence) || a.capability.localeCompare(b.capability))
}

function detectPackerIndicators(input: {
  sections: ReSection[]
  imports: ReImport[]
  strings: ReStringRecord[]
  entropy: number
}): Array<{ indicator: string; confidence: 'low' | 'medium' | 'high'; evidence: string[] }> {
  const indicators: Array<{ indicator: string; confidence: 'low' | 'medium' | 'high'; evidence: string[] }> = []
  const sectionNames = input.sections.map((section) => section.name)
  const highEntropySections = input.sections.filter((section) => (section.entropy ?? 0) >= 7.2)
  const importCount = flattenImports(input.imports).length
  const stringValues = input.strings.map((entry) => entry.value)
  const upxEvidence = [...sectionNames, ...stringValues].filter((value) => /UPX|\.aspack|themida|vmp|mpress|petite/i.test(value))
  if (upxEvidence.length) {
    indicators.push({ indicator: 'known packer marker', confidence: 'high', evidence: uniqueSorted(upxEvidence).slice(0, 20) })
  }
  if (highEntropySections.length) {
    indicators.push({
      indicator: 'high entropy section data',
      confidence: highEntropySections.length >= 2 ? 'high' : 'medium',
      evidence: highEntropySections.map((section) => `${section.name}: entropy ${section.entropy}`)
    })
  }
  const writableExecutable = input.sections.filter((section) =>
    section.flags?.some((flag) => /exec/i.test(flag)) && section.flags?.some((flag) => /write/i.test(flag))
  )
  if (writableExecutable.length) {
    indicators.push({
      indicator: 'writable executable section',
      confidence: 'medium',
      evidence: writableExecutable.map((section) => section.name)
    })
  }
  if (input.entropy >= 7.2) {
    indicators.push({ indicator: 'high overall file entropy', confidence: 'medium', evidence: [`overall entropy ${input.entropy}`] })
  }
  if (importCount > 0 && importCount <= 5 && sectionNames.length > 0) {
    indicators.push({ indicator: 'very small import table', confidence: 'low', evidence: [`${importCount} imports`] })
  }
  return indicators
}

function findCryptoConstants(buffer: Buffer): Array<{ name: string; offset?: number; evidence: string }> {
  const patterns: Array<[string, Buffer]> = [
    ['AES S-box prefix', Buffer.from('637c777bf26b6fc53001672bfed7ab76', 'hex')],
    ['AES inverse S-box prefix', Buffer.from('52096ad53036a538bf40a39e81f3d7fb', 'hex')],
    ['SHA-256 K constants prefix little-endian', Buffer.from('982f8a42877491b5', 'hex')],
    ['MD5 constants prefix little-endian', Buffer.from('78a46ad756b7c7e8', 'hex')]
  ]
  const out: Array<{ name: string; offset?: number; evidence: string }> = []
  for (const [name, pattern] of patterns) {
    const offset = buffer.indexOf(pattern)
    if (offset >= 0) out.push({ name, offset, evidence: `matched ${pattern.length} byte signature at ${hex(offset)}` })
  }
  return out
}

function recommendTargets(input: {
  sections: ReSection[]
  imports: ReImport[]
  strings: ReStringRecord[]
  capabilities: ReCapability[]
  iocs: ReIocs
  packerIndicators: Array<{ indicator: string; confidence: string; evidence: string[] }>
}): string[] {
  const targets = [
    ...input.capabilities.flatMap((capability) => capability.evidence.slice(0, 3).map((item) => `Capability evidence: ${item}`)),
    ...input.strings.slice(0, 15).map((entry) => `String ${hex(entry.offset)}: ${entry.value.slice(0, 120)}`),
    ...input.sections
      .filter((section) => (section.entropy ?? 0) >= 7.2 || section.flags?.includes('executable'))
      .map((section) => `Section ${section.name} (${section.flags?.join(', ') || 'flags unknown'}, entropy ${section.entropy ?? 'n/a'})`),
    ...input.packerIndicators.flatMap((indicator) => indicator.evidence.map((item) => `Packer indicator: ${indicator.indicator}: ${item}`)),
    ...input.iocs.urls.slice(0, 10).map((ioc) => `URL IOC: ${ioc}`),
    ...input.iocs.domains.slice(0, 10).map((ioc) => `Domain IOC: ${ioc}`)
  ]
  return uniqueSorted(targets).slice(0, 50)
}

function buildTriageSummary(input: {
  fileInfo: Awaited<ReturnType<typeof analyzeFileInfo>>
  imports: ReImport[]
  iocs: ReIocs
  capabilities: ReCapability[]
  packerIndicators: Array<{ indicator: string; confidence: string }>
}): string {
  const topCaps = input.capabilities.slice(0, 5).map((entry) => `${entry.capability} (${entry.confidence})`).join(', ') || 'none detected'
  const iocCount = Object.values(iocCounts(input.iocs)).reduce((sum, count) => sum + count, 0)
  const importCount = flattenImports(input.imports).length
  const packer = input.packerIndicators.length
    ? input.packerIndicators.map((entry) => `${entry.indicator} (${entry.confidence})`).join(', ')
    : 'no strong packer indicators'
  return `${input.fileInfo.fileName} is ${input.fileInfo.format.format}${input.fileInfo.format.arch ? ` ${input.fileInfo.format.arch}` : ''}, ${input.fileInfo.size} bytes, SHA-256 ${input.fileInfo.hashes.sha256}. Parsed ${importCount} imports and ${iocCount} IOC candidates. Capability hints: ${topCaps}. Packing: ${packer}.`
}

function renderReport(input: {
  state: ReAnalysisState
  sample?: ReSampleState
  iocs: ReIocs
  symbols: ReSymbolsState
  notes: string
  behaviorGraph?: unknown
}): string {
  const sample = input.sample
  const caps = sample?.capabilities ?? []
  const sections = sample?.sections ?? []
  const imports = sample?.imports ?? []
  const exports = sample?.exports ?? []
  const packers = sample?.packerIndicators ?? []
  const report = [
    '# Reverse Engineering Report',
    '',
    '## Executive Summary',
    '',
    sample
      ? `${sample.fileName} (${sample.path}) is currently tracked as the active sample. ${sample.format?.format ?? 'Unknown format'}${sample.format?.arch ? `, ${sample.format.arch}` : ''}.`
      : 'No active sample is currently tracked.',
    '',
    '## Scope',
    '',
    `Workspace analysis state last updated: ${input.state.updatedAt}`,
    '',
    '## Sample Metadata',
    '',
    sample
      ? [
          `- Path: ${sample.path}`,
          `- Size: ${sample.size ?? 'unknown'}`,
          `- Format: ${sample.format?.format ?? 'unknown'}`,
          `- Architecture: ${sample.format?.arch ?? 'unknown'}`
        ].join('\n')
      : '- No sample metadata available.',
    '',
    '## Hashes',
    '',
    sample?.hashes
      ? [
          `- MD5: ${sample.hashes.md5}`,
          `- SHA1: ${sample.hashes.sha1}`,
          `- SHA256: ${sample.hashes.sha256}`,
          `- SHA512: ${sample.hashes.sha512}`
        ].join('\n')
      : '- No hashes available.',
    '',
    '## Format and Architecture',
    '',
    sample?.format ? fencedJson(sample.format) : 'No format details available.',
    '',
    '## Static Analysis Summary',
    '',
    `- Imports: ${flattenImports(imports).length}`,
    `- Exports: ${exports.length}`,
    `- Capabilities: ${caps.length}`,
    `- IOC categories with values: ${Object.entries(iocCounts(input.iocs)).filter(([, count]) => count > 0).length}`,
    '',
    '## Sections and Entropy',
    '',
    sections.length
      ? markdownTable(['Name', 'VA', 'Raw offset', 'Raw size', 'Entropy', 'Flags'], sections.slice(0, 80).map((section) => [
          section.name,
          section.virtualAddress ?? '',
          String(section.rawOffset ?? ''),
          String(section.rawSize ?? ''),
          String(section.entropy ?? ''),
          section.flags?.join(', ') ?? ''
        ]))
      : 'No sections or segments parsed.',
    '',
    '## Imports and Exports',
    '',
    imports.length
      ? imports.slice(0, 40).map((entry) => `- ${entry.library}: ${entry.symbols.slice(0, 25).join(', ')}`).join('\n')
      : '- No imports parsed.',
    '',
    exports.length ? `Exports: ${exports.slice(0, 80).map((entry) => entry.name).join(', ')}` : 'Exports: none parsed.',
    '',
    '## Strings of Interest',
    '',
    sample?.toolSummaries?.strings ? fencedJson(sample.toolSummaries.strings) : 'See `.re-mode/raw/` for strings output when extracted.',
    '',
    '## Capabilities',
    '',
    caps.length
      ? caps.map((cap) => `- ${cap.capability} (${cap.confidence}): ${cap.evidence.slice(0, 10).join(', ')}`).join('\n')
      : '- No capability hints recorded.',
    '',
    '## IOCs',
    '',
    renderIocs(input.iocs),
    '',
    '## Function Analysis',
    '',
    Object.keys(input.symbols.functions).length
      ? fencedJson(input.symbols.functions)
      : 'No function-level analysis has been saved yet.',
    '',
    '## Crypto / Encoding Findings',
    '',
    sample?.cryptoCandidates ? fencedJson(sample.cryptoCandidates) : 'No crypto workflow output saved yet.',
    '',
    '## Protected / Obfuscated Binary Findings',
    '',
    renderBehaviorGraphSummary(input.behaviorGraph),
    '',
    '## Diff Findings',
    '',
    'See `.re-mode/diffs/` for saved binary diff outputs.',
    '',
    '## Current Hypotheses',
    '',
    input.state.hypotheses.length ? input.state.hypotheses.map((item) => `- ${item}`).join('\n') : '- No hypotheses recorded.',
    '',
    '## Confidence Levels',
    '',
    caps.length ? caps.map((cap) => `- ${cap.capability}: ${cap.confidence}`).join('\n') : '- No confidence-scored findings recorded.',
    '',
    '## Limitations',
    '',
    '- This report is based on available local static-analysis tooling and Kun RE Mode heuristics.',
    '- Function-level disassembly/decompilation requires optional external tools such as rizin, radare2, Ghidra, objdump, capa, or jadx.',
    '',
    '## Recommended Next Steps',
    '',
    sample?.recommendedTargets?.length
      ? sample.recommendedTargets.map((item) => `- ${item}`).join('\n')
      : '- Run `re_triage`, `re_find_crypto`, or inspect candidate imports/strings in a disassembler.',
    '',
    '## Appendix: Tool Output Summaries',
    '',
    sample?.toolSummaries ? fencedJson(sample.toolSummaries) : 'No tool summaries saved.',
    '',
    '## Notes',
    '',
    input.notes.trim() || 'No notes saved.'
  ]
  return report.join('\n')
}

function renderBehaviorGraphSummary(raw: unknown): string {
  if (!raw || typeof raw !== 'object') {
    return 'No behavior graph has been built yet. Run `re_build_behavior_graph` or `re_protection_indicators` for protected-binary findings.'
  }
  const graph = raw as {
    nodes?: unknown[]
    edges?: unknown[]
    stages?: Array<{ id?: string; label?: string; confidence?: string; nodes?: unknown[] }>
    targets?: Array<{ rank?: number; id?: string; label?: string; confidence?: string; score?: number; reasons?: unknown[]; recommendedAction?: string }>
    knownUnknowns?: unknown[]
  }
  const lines = [
    `- Graph nodes: ${graph.nodes?.length ?? 0}`,
    `- Graph edges: ${graph.edges?.length ?? 0}`,
    `- Stages: ${graph.stages?.length ?? 0}`,
    `- High-value targets: ${graph.targets?.length ?? 0}`,
    '',
    '### Suspected Execution Stages',
    ''
  ]
  if (graph.stages?.length) {
    for (const stage of graph.stages.slice(0, 12)) {
      lines.push(`- ${stage.label ?? stage.id ?? 'unknown'} (${stage.confidence ?? 'unknown'}): ${(stage.nodes ?? []).length} node(s)`)
    }
  } else {
    lines.push('- No staged execution model recorded.')
  }
  lines.push('', '### High-Value RE Targets', '')
  if (graph.targets?.length) {
    for (const target of graph.targets.slice(0, 15)) {
      const reasons = Array.isArray(target.reasons)
        ? target.reasons.filter((item): item is string => typeof item === 'string').slice(0, 3).join('; ')
        : ''
      lines.push(`- #${target.rank ?? '?'} ${target.label ?? target.id ?? 'unknown'} (${target.confidence ?? 'unknown'}, score ${target.score ?? '?'})${reasons ? `: ${reasons}` : ''}`)
    }
  } else {
    lines.push('- No ranked protected-binary targets recorded.')
  }
  lines.push('', '### Known Unknowns', '')
  const knownUnknowns = Array.isArray(graph.knownUnknowns)
    ? graph.knownUnknowns.filter((item): item is string => typeof item === 'string')
    : []
  lines.push(...(knownUnknowns.length ? knownUnknowns.slice(0, 12).map((item) => `- ${item}`) : ['- No known unknowns recorded.']))
  return lines.join('\n')
}

function renderIocs(iocs: ReIocs): string {
  const lines: string[] = []
  for (const [key, values] of Object.entries(iocs) as Array<[keyof ReIocs, string[]]>) {
    if (!values.length) continue
    lines.push(`### ${key}`, '', ...values.slice(0, 100).map((value) => `- ${value}`), '')
  }
  return lines.length ? lines.join('\n') : 'No IOCs recorded.'
}

function markdownTable(headers: string[], rows: string[][]): string {
  const escape = (value: string) => value.replaceAll('|', '\\|').replace(/\s+/g, ' ').trim()
  return [
    `| ${headers.map(escape).join(' | ')} |`,
    `| ${headers.map(() => '---').join(' | ')} |`,
    ...rows.map((row) => `| ${row.map(escape).join(' | ')} |`)
  ].join('\n')
}

function fencedJson(value: unknown): string {
  return `\`\`\`json\n${JSON.stringify(value, null, 2)}\n\`\`\``
}

function rollingEntropy(buffer: Buffer, windowSize: number): Array<{ offset: number; entropy: number }> {
  const out: Array<{ offset: number; entropy: number }> = []
  const step = Math.max(1, windowSize)
  for (let offset = 0; offset < buffer.length; offset += step) {
    out.push({ offset, entropy: entropy(buffer.subarray(offset, Math.min(buffer.length, offset + windowSize))) })
  }
  return out
}

function flattenImports(imports: ReImport[]): string[] {
  return imports.flatMap((entry) => entry.symbols.map((symbol) => `${entry.library}!${symbol}`))
}

function diffNamed(a: string[], b: string[]): { added: string[]; removed: string[]; changed: string[] } {
  const normalizeName = (value: string) => value.split(':')[0] ?? value
  const aByName = new Map(a.map((value) => [normalizeName(value), value]))
  const bByName = new Map(b.map((value) => [normalizeName(value), value]))
  const added = [...bByName.keys()].filter((name) => !aByName.has(name))
  const removed = [...aByName.keys()].filter((name) => !bByName.has(name))
  const changed = [...bByName.keys()].filter((name) => aByName.has(name) && aByName.get(name) !== bByName.get(name))
  return { added, removed, changed }
}

function diffSets(a: string[], b: string[], limit: number): { added: string[]; removed: string[] } {
  const aSet = new Set(a)
  const bSet = new Set(b)
  return {
    added: [...bSet].filter((value) => !aSet.has(value)).slice(0, limit),
    removed: [...aSet].filter((value) => !bSet.has(value)).slice(0, limit)
  }
}

function createIocBuckets(): ReIocs {
  return {
    urls: [],
    domains: [],
    ipv4: [],
    ipv6: [],
    emails: [],
    registryKeys: [],
    windowsPaths: [],
    unixPaths: [],
    fileNames: [],
    mutexes: [],
    userAgents: [],
    powershellCommands: [],
    shellCommands: [],
    base64Blobs: [],
    hexBlobs: [],
    cryptoConstants: [],
    suspiciousApis: []
  }
}

function sortIocs(iocs: ReIocs): ReIocs {
  return Object.fromEntries(
    Object.entries(iocs).map(([key, values]) => [key, uniqueSorted(values).slice(0, 1000)])
  ) as ReIocs
}

function iocCounts(iocs: ReIocs): Record<keyof ReIocs, number> {
  return Object.fromEntries(Object.entries(iocs).map(([key, values]) => [key, values.length])) as Record<keyof ReIocs, number>
}

function addIoc(bucket: string[], value: string): void {
  const normalized = value.trim()
  if (!normalized || normalized.length > 2048) return
  bucket.push(normalized)
}

function suspiciousApiNames(value: string): string[] {
  return uniqueSorted([...value.matchAll(SUSPICIOUS_API_EXTRACT_PATTERN)].map((match) => match[0]))
}

function pushString(out: ReStringRecord[], entry: ReStringRecord, maxStrings: number): void {
  if (out.length >= maxStrings) return
  const value = entry.value.trim()
  if (!value || value.length > 4096) return
  out.push({ ...entry, value, tags: stringTags(value) })
}

function stringTags(value: string): string[] {
  const tags: string[] = []
  if (URL_PATTERN.test(value)) tags.push('url')
  URL_PATTERN.lastIndex = 0
  if (IPV4_PATTERN.test(value)) tags.push('ipv4')
  IPV4_PATTERN.lastIndex = 0
  if (DOMAIN_PATTERN.test(value)) tags.push('domain')
  DOMAIN_PATTERN.lastIndex = 0
  if (REGISTRY_PATTERN.test(value)) tags.push('registry')
  REGISTRY_PATTERN.lastIndex = 0
  if (WINDOWS_PATH_PATTERN.test(value) || UNIX_PATH_PATTERN.test(value)) tags.push('path')
  WINDOWS_PATH_PATTERN.lastIndex = 0
  UNIX_PATH_PATTERN.lastIndex = 0
  if (SUSPICIOUS_API_PATTERN.test(value)) tags.push('api')
  SUSPICIOUS_API_PATTERN.lastIndex = 0
  if (CRYPTO_PATTERN.test(value)) tags.push('crypto')
  CRYPTO_PATTERN.lastIndex = 0
  if (POWERSHELL_PATTERN.test(value) || SHELL_COMMAND_PATTERN.test(value)) tags.push('command')
  POWERSHELL_PATTERN.lastIndex = 0
  SHELL_COMMAND_PATTERN.lastIndex = 0
  if (BASE64_PATTERN.test(value)) tags.push('base64-like')
  BASE64_PATTERN.lastIndex = 0
  return tags
}

function rvaToOffset(rva: number, sections: ReSection[]): number | null {
  for (const section of sections) {
    const va = parseHexNumber(section.virtualAddress)
    const rawOffset = section.rawOffset ?? 0
    const size = Math.max(section.virtualSize ?? 0, section.rawSize ?? 0)
    if (va == null || size <= 0) continue
    if (rva >= va && rva < va + size) return rawOffset + (rva - va)
  }
  return rva < 0x1000 ? rva : null
}

function sliceRange(buffer: Buffer, offset: number, size: number): Buffer {
  if (!Number.isFinite(offset) || !Number.isFinite(size) || offset < 0 || size <= 0 || offset >= buffer.length) return Buffer.alloc(0)
  return buffer.subarray(offset, Math.min(buffer.length, offset + size))
}

function findEndOfCentralDirectory(buffer: Buffer): number | null {
  const min = Math.max(0, buffer.length - 0xffff - 22)
  for (let offset = buffer.length - 22; offset >= min; offset -= 1) {
    if (readUInt32LE(buffer, offset) === 0x06054b50) return offset
  }
  return null
}

function findExecutable(command: string): string {
  const lookup = process.platform === 'win32'
    ? spawnSync('where.exe', [command], { encoding: 'utf8' })
    : spawnSync('sh', ['-lc', `command -v ${shellQuote(command)}`], { encoding: 'utf8' })
  if (lookup.status !== 0) return ''
  return lookup.stdout.split(/\r?\n/).map((line) => line.trim()).find(Boolean) ?? ''
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`
}

function emptyAnalysisState(): ReAnalysisState {
  return { version: 1, samples: {}, hypotheses: [], recommendedTargets: [], updatedAt: nowIso() }
}

function emptySymbolsState(): ReSymbolsState {
  return { version: 1, functions: {}, variables: {}, labels: {}, updatedAt: nowIso() }
}

function normalizeAnalysisState(raw: unknown): ReAnalysisState {
  if (!raw || typeof raw !== 'object') return emptyAnalysisState()
  const input = raw as Partial<ReAnalysisState>
  return {
    version: 1,
    ...(typeof input.currentSample === 'string' ? { currentSample: input.currentSample } : {}),
    samples: input.samples && typeof input.samples === 'object' ? input.samples : {},
    hypotheses: Array.isArray(input.hypotheses) ? input.hypotheses.filter((item): item is string => typeof item === 'string') : [],
    recommendedTargets: Array.isArray(input.recommendedTargets) ? input.recommendedTargets.filter((item): item is string => typeof item === 'string') : [],
    updatedAt: typeof input.updatedAt === 'string' ? input.updatedAt : nowIso()
  }
}

function normalizeSymbolsState(raw: unknown): ReSymbolsState {
  if (!raw || typeof raw !== 'object') return emptySymbolsState()
  const input = raw as Partial<ReSymbolsState>
  return {
    version: 1,
    functions: input.functions && typeof input.functions === 'object' ? input.functions : {},
    variables: input.variables && typeof input.variables === 'object' ? input.variables : {},
    labels: input.labels && typeof input.labels === 'object' ? input.labels : {},
    updatedAt: typeof input.updatedAt === 'string' ? input.updatedAt : nowIso()
  }
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, 'utf8')) as unknown
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
}

function nowIso(): string {
  return new Date().toISOString()
}

function sanitizeFileName(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 180)
}

function normalizePath(value: string): string {
  return value.replaceAll('\\', '/')
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b))
}

function clampInt(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, Math.floor(value)))
}

function round(value: number, digits: number): number {
  const scale = 10 ** digits
  return Math.round(value * scale) / scale
}

function confidenceRank(value: 'low' | 'medium' | 'high'): number {
  return value === 'high' ? 3 : value === 'medium' ? 2 : 1
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function readFixedAscii(buffer: Buffer, offset: number, length: number): string {
  if (offset < 0 || offset >= buffer.length) return ''
  const end = Math.min(buffer.length, offset + length)
  const nul = buffer.indexOf(0, offset)
  return buffer.toString('ascii', offset, nul >= offset && nul < end ? nul : end).trim()
}

function readCString(buffer: Buffer, offset: number, maxLength: number): string {
  if (offset < 0 || offset >= buffer.length) return ''
  const endLimit = Math.min(buffer.length, offset + maxLength)
  const nul = buffer.indexOf(0, offset)
  const end = nul >= offset && nul < endLimit ? nul : endLimit
  return buffer.toString('utf8', offset, end).replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '').trim()
}

function isPrintableByte(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0d || (byte >= 0x20 && byte <= 0x7e)
}

function printableAsciiRatio(buffer: Buffer): number {
  if (buffer.length === 0) return 0
  let printable = 0
  for (const byte of buffer) {
    if (isPrintableByte(byte)) printable += 1
  }
  return round(printable / buffer.length, 3)
}

function hex(value: number | bigint): string {
  const raw = typeof value === 'bigint' ? value.toString(16) : Math.max(0, Math.floor(value)).toString(16)
  return `0x${raw}`
}

function parseHexNumber(value: string | undefined): number | null {
  if (!value) return null
  const parsed = Number.parseInt(value.replace(/^0x/i, ''), 16)
  return Number.isFinite(parsed) ? parsed : null
}

function readUInt16LE(buffer: Buffer, offset: number): number | null {
  return offset >= 0 && offset + 2 <= buffer.length ? buffer.readUInt16LE(offset) : null
}

function readUInt32LE(buffer: Buffer, offset: number): number | null {
  return offset >= 0 && offset + 4 <= buffer.length ? buffer.readUInt32LE(offset) : null
}

function readUInt32BE(buffer: Buffer, offset: number): number | null {
  return offset >= 0 && offset + 4 <= buffer.length ? buffer.readUInt32BE(offset) : null
}

function readBigUInt64LE(buffer: Buffer, offset: number): bigint | null {
  return offset >= 0 && offset + 8 <= buffer.length ? buffer.readBigUInt64LE(offset) : null
}

function readUInt16(buffer: Buffer, offset: number, endian: 'little' | 'big'): number | null {
  return offset >= 0 && offset + 2 <= buffer.length
    ? endian === 'little' ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset)
    : null
}

function readUInt32(buffer: Buffer, offset: number, endian: 'little' | 'big'): number | null {
  return offset >= 0 && offset + 4 <= buffer.length
    ? endian === 'little' ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset)
    : null
}

function readBigUInt64(buffer: Buffer, offset: number, endian: 'little' | 'big'): bigint | null {
  return offset >= 0 && offset + 8 <= buffer.length
    ? endian === 'little' ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset)
    : null
}

function peMachineArch(machine: number): string {
  const map: Record<number, string> = {
    0x14c: 'x86',
    0x8664: 'x86_64',
    0x1c0: 'ARM',
    0x1c4: 'ARMv7',
    0xaa64: 'ARM64',
    0x200: 'IA64'
  }
  return map[machine] ?? `machine_${hex(machine)}`
}

function peSubsystemName(value: number): string {
  const map: Record<number, string> = {
    1: 'native',
    2: 'windows_gui',
    3: 'windows_console',
    7: 'posix_console',
    9: 'windows_ce_gui',
    10: 'efi_application',
    11: 'efi_boot_service_driver',
    12: 'efi_runtime_driver',
    14: 'xbox',
    16: 'windows_boot_application'
  }
  return map[value] ?? `subsystem_${value}`
}

function peSectionFlags(value: number): string[] {
  const flags: string[] = []
  if ((value & 0x20) !== 0) flags.push('code')
  if ((value & 0x40) !== 0) flags.push('initialized-data')
  if ((value & 0x80) !== 0) flags.push('uninitialized-data')
  if ((value & 0x20000000) !== 0) flags.push('executable')
  if ((value & 0x40000000) !== 0) flags.push('readable')
  if ((value & 0x80000000) !== 0) flags.push('writable')
  return flags
}

function elfMachineArch(value: number): string {
  const map: Record<number, string> = {
    3: 'x86',
    8: 'MIPS',
    20: 'PowerPC',
    40: 'ARM',
    62: 'x86_64',
    183: 'AArch64',
    243: 'RISC-V'
  }
  return map[value] ?? `machine_${value}`
}

function elfTypeName(value: number): string {
  const map: Record<number, string> = {
    0: 'none',
    1: 'relocatable',
    2: 'executable',
    3: 'shared_object',
    4: 'core'
  }
  return map[value] ?? `type_${value}`
}

function elfOsAbi(value: number): string {
  const map: Record<number, string> = {
    0: 'System V',
    3: 'Linux',
    6: 'Solaris',
    9: 'FreeBSD'
  }
  return map[value] ?? `abi_${value}`
}

function elfSectionType(value: number): string {
  const map: Record<number, string> = {
    0: 'NULL',
    1: 'PROGBITS',
    2: 'SYMTAB',
    3: 'STRTAB',
    4: 'RELA',
    6: 'DYNAMIC',
    7: 'NOTE',
    8: 'NOBITS',
    9: 'REL',
    11: 'DYNSYM'
  }
  return map[value] ?? `type_${value}`
}

function elfSectionFlags(value: number): string[] {
  const flags: string[] = []
  if ((value & 0x1) !== 0) flags.push('writable')
  if ((value & 0x2) !== 0) flags.push('allocated')
  if ((value & 0x4) !== 0) flags.push('executable')
  return flags
}

function elfSymbolType(value: number): string {
  const map: Record<number, string> = {
    0: 'notype',
    1: 'object',
    2: 'function',
    3: 'section',
    4: 'file',
    6: 'tls'
  }
  return map[value] ?? `type_${value}`
}

function machoCpuArch(value: number): string {
  const masked = value & 0x00ffffff
  if (masked === 7 && (value & 0x01000000) !== 0) return 'x86_64'
  if (masked === 7) return 'x86'
  if (masked === 12 && (value & 0x01000000) !== 0) return 'arm64'
  if (masked === 12) return 'arm'
  return `cpu_${hex(value)}`
}

function machoFileType(value: number): string {
  const map: Record<number, string> = {
    1: 'object',
    2: 'executable',
    3: 'fixed_vm_library',
    4: 'core',
    5: 'preload',
    6: 'dylib',
    7: 'dylinker',
    8: 'bundle',
    10: 'dSYM',
    11: 'kext'
  }
  return map[value] ?? `type_${value}`
}

const URL_PATTERN = /\bhttps?:\/\/[^\s"'<>\\]+/gi
const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const IPV6_PATTERN = /\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b/gi
const DOMAIN_PATTERN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|uk|de|jp|kr|br|in|edu|gov|mil|dev|app|online|site|cloud|shop|me|us)\b/gi
const REGISTRY_PATTERN = /\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT)\\[^\s"'<>]+/gi
const WINDOWS_PATH_PATTERN = /\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/g
const UNIX_PATH_PATTERN = /(^|\s)(\/[A-Za-z0-9._@%+~:-]+(?:\/[A-Za-z0-9._@%+~:-]+)+)/g
const USER_AGENT_PATTERN = /\b(?:Mozilla\/|User-Agent:|curl\/|Wget\/|python-requests\/)/i
const POWERSHELL_PATTERN = /\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|FromBase64String|EncodedCommand|-enc\b)/i
const SHELL_COMMAND_PATTERN = /\b(?:cmd\.exe|\/bin\/sh|\/bin\/bash|chmod\s+\+x|wget\s+|curl\s+|certutil\s+-urlcache)\b/i
const BASE64_PATTERN = /^[A-Za-z0-9+/]{24,}={0,2}$/
const HEX_BLOB_PATTERN = /^(?:0x)?[A-Fa-f0-9]{32,}$/
const MUTEX_PATTERN = /\b(?:Global\\|Local\\|Mutex|Mutant|Session\\)[A-Za-z0-9_.\\-{}]{6,}/i
const SUSPICIOUS_API_PATTERN = /\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|NtProtectVirtualMemory|WriteProcessMemory|CreateRemoteThread|LoadLibrary(?:A|W)?|GetProcAddress|LdrGetProcedureAddress|InternetOpen|HttpSendRequest|WinHttp|RegSetValue|CreateService|IsDebuggerPresent|CryptUnprotectData|GetAsyncKeyState|ShellExecute|CreateProcess)\b/i
const SUSPICIOUS_API_EXTRACT_PATTERN = /\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|NtProtectVirtualMemory|WriteProcessMemory|CreateRemoteThread|LoadLibrary(?:A|W)?|GetProcAddress|LdrGetProcedureAddress|InternetOpen|HttpSendRequest|WinHttp|RegSetValue|CreateService|IsDebuggerPresent|CryptUnprotectData|GetAsyncKeyState|ShellExecute|CreateProcess)\b/gi
const CRYPTO_PATTERN = /\b(?:AES|RC4|RSA|SHA-?1|SHA-?256|MD5|HMAC|BCrypt|Crypt|OpenSSL|mbedTLS|libsodium|base64|xor|inflate|deflate)\b/i
const IOC_HINT_PATTERN = /https?:\/\/|(?:\d{1,3}\.){3}\d{1,3}|HKEY_|HKLM|HKCU|powershell|cmd\.exe|[a-z0-9.-]+\.(?:com|net|org|ru|cn|io)\b/i

function isValidIpv4(value: string): boolean {
  return value.split('.').every((part) => {
    const number = Number(part)
    return Number.isInteger(number) && number >= 0 && number <= 255
  })
}

function trimPunctuation(value: string): string {
  return value.replace(/[),.;\]}>'"]+$/g, '')
}

function looksLikeFileName(value: string): boolean {
  return /\.(dll|exe|sys|dat|bin|tmp|txt|json|xml|config|ini)$/i.test(value)
}

function maybeFileName(value: string): string {
  const trimmed = trimPunctuation(value)
  if (/^[A-Za-z0-9_. -]+\.(?:exe|dll|sys|scr|bat|cmd|ps1|vbs|js|dat|bin|tmp|cfg|ini|json|xml)$/i.test(trimmed)) {
    return trimmed
  }
  return ''
}
