// The deterministic part of the repository panel: which repository a session is
// in, the SVL queries for its alerts and assets, and how Orca's answers become
// rows. Calls happen only through the `call` that `pagesOf` is handed.

import type { AlertRow, AssetRow, RiskFilter, RiskLevel, Section } from '../../types'

export const RISK_LEVELS: readonly RiskLevel[] = ['critical', 'high', 'medium', 'low', 'informational']

/** The risks the panel shows. Low and informational are left out of its lists, counts and totals. */
export const SHOWN_RISKS: readonly RiskLevel[] = ['critical', 'high', 'medium']

/** A filter the panel can apply: a risk it no longer shows (one chosen before) reads as all. */
export function shownFilter(filter: RiskFilter): RiskFilter {
  return filter === 'all' || SHOWN_RISKS.includes(filter) ? filter : 'all'
}

export const SECTIONS: readonly Section[] = ['code', 'cloud', 'assets']

export const OPEN_STATUSES = ['open', 'in_progress'] as const

/** How many rows an open section lists. */
export const SHOWN = 25

/**
 * Rows per list call. Orca answers every row whole (a code alert carries its code
 * snippets and dataflow trace, about 15 KB; an asset its compliance list, about
 * 6 KB) whatever `select` says, and an MCP answer past the client's output cap
 * comes back as an "Error: result ... exceeds maximum allowed tokens" text in
 * place of JSON. Small pages stay under it; one that does not is fetched again
 * in halves.
 */
export const PAGE_SIZE = 5

export const ORCA_APP = 'https://app.orcasecurity.io'

/**
 * `owner/repo` (or `group/subgroup/repo`) from an origin remote, as Orca names a
 * code repository. Orca matches the name without regard to case.
 *   https://github.com/example-org/web-app.git  -> example-org/web-app
 *   git@github.com:example-org/web-app.git      -> example-org/web-app
 *   ssh://git@gitlab.com:22/team/sub/app.git    -> team/sub/app
 */
export function repoNameOf(remote: string | null | undefined): string | null {
  if (typeof remote !== 'string' || remote.trim() === '') {
    return null
  }
  const raw = remote.trim()
  const scp = /^[\w.-]+@[^:/]+:(?!\/)(.+)$/.exec(raw)
  let path: string | undefined = scp?.[1]
  if (path === undefined) {
    try {
      path = new URL(raw).pathname
    } catch {
      return null
    }
  }
  const name = path
    .replace(/^\/+/, '')
    .replace(/\/+$/, '')
    .replace(/\.git$/, '')
  return name.includes('/') ? name : null
}

type Condition = Record<string, unknown>

function and(values: Condition[]): Condition {
  return values.length === 1 && values[0] !== undefined ? values[0] : { type: 'operation', operator: 'and', values }
}

function riskIs(filter: RiskFilter): Condition {
  const values = shownFilter(filter) === 'all' ? [...SHOWN_RISKS] : [filter]
  return { type: 'str', key: 'RiskLevel', operator: 'in', values }
}

const isOpen: Condition = { type: 'str', key: 'Status', operator: 'in', values: [...OPEN_STATUSES] }

/** The code repository itself, as an alert's inventory. */
function theRepository(repo: string): Condition {
  return {
    type: 'object_set',
    models: ['Inventory'],
    keys: ['Inventories'],
    operator: 'has',
    with: and([
      { type: 'str', key: 'NewSubCategory', operator: 'in', values: ['Code Repository'] },
      { type: 'str', key: 'Name', operator: 'in', values: [repo] },
    ]),
  }
}

/** An inventory item whose Code Origin is the repository: something it deployed. */
function deployedFrom(repo: string): Condition {
  return {
    type: 'object_set',
    models: ['CodeOrigin'],
    keys: ['CodeOrigins'],
    operator: 'has',
    with: {
      type: 'object',
      models: ['CodeRepository'],
      keys: ['CodeRepository'],
      operator: 'has',
      with: { type: 'str', key: 'Name', operator: 'in', values: [repo] },
    },
  }
}

/**
 * What a section lists, as the Orca UI's Discovery runs it, for the risks the
 * panel shows (or the one chosen):
 *   code   - open alerts on the repository (SAST, SCA, IaC, secrets)
 *   cloud  - open alerts on cloud assets deployed from it
 *   assets - the cloud assets deployed from it
 */
export function sectionQuery(section: Section, repo: string, filter: RiskFilter = 'all'): Condition {
  return scoped(section, repo, riskIs(filter))
}

/** A section's query, narrowed by risk where `risk` is given. */
function scoped(section: Section, repo: string, risk: Condition | null): Condition {
  const narrowed = (conditions: Condition[]) => and(risk === null ? conditions : [...conditions, risk])
  if (section === 'assets') {
    return { type: 'object_set', models: ['Inventory'], with: narrowed([deployedFrom(repo)]) }
  }
  const scope =
    section === 'code'
      ? theRepository(repo)
      : { type: 'object_set', models: ['Inventory'], keys: ['Inventories'], operator: 'has', with: deployedFrom(repo) }
  return { type: 'object_set', models: ['Alert'], keys: ['Alert'], with: narrowed([isOpen, scope]) }
}

export type SvlArgs = {
  query: Condition
  order_by?: string[]
  group_by?: string[]
  limit: number
  offset?: number
}

export type McpAnswer = { content: ReadonlyArray<{ type: string; text?: string }>; isError?: boolean }

/** A section's top `shown` rows by Orca score, in pages of PAGE_SIZE. */
export function listCalls(section: Section, repo: string, filter: RiskFilter, shown: number = SHOWN): SvlArgs[] {
  const query = sectionQuery(section, repo, filter)
  const pages: SvlArgs[] = []
  for (let offset = 0; offset < shown; offset += PAGE_SIZE) {
    pages.push({ query, order_by: ['-OrcaScore'], limit: Math.min(PAGE_SIZE, shown - offset), offset })
  }
  return pages
}

/** A section's counts by risk level, for every risk the panel shows (not narrowed by the chosen one). */
export function countsCall(section: Section, repo: string): SvlArgs {
  return { query: sectionQuery(section, repo), group_by: ['RiskLevel'], limit: 10 }
}

/**
 * A section's counts over every risk, low and informational too. Asked only of
 * an empty Cloud or Assets tab, to say why it is empty: nothing traced to the
 * repository, or only risks the panel leaves out.
 */
export function everyRiskCall(section: Section, repo: string): SvlArgs {
  return { query: scoped(section, repo, null), group_by: ['RiskLevel'], limit: 10 }
}

export function alertUrl(id: string): string {
  return `${ORCA_APP}/alerts/${encodeURIComponent(id)}`
}

export function assetUrl(id: string): string {
  return `${ORCA_APP}/inventory/${encodeURIComponent(id)}`
}

export type Svl = { status?: unknown; data?: unknown; total_items?: unknown }

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function textOf(content: McpAnswer['content']): string {
  return content
    .filter(block => block.type === 'text' && typeof block.text === 'string')
    .map(block => block.text)
    .join('')
}

/** Whether the MCP client refused to hand the answer back for its size. */
export function tooLarge(answer: McpAnswer): boolean {
  return /exceeds maximum allowed tokens/i.test(textOf(answer.content).slice(0, 500))
}

/**
 * Where the MCP client saved an answer it would not hand back, as its message
 * names it: only a file in a session's tool-results folder, never another path
 * the words might name.
 */
export function savedPathOf(answer: McpAnswer): string | null {
  const match = /saved to (\/.+?\.(?:txt|json))\b/.exec(textOf(answer.content).slice(0, 2000))
  const path = match?.[1]
  return path !== undefined && /\/\.claude\/projects\/[^/]+\/[^/]+\/tool-results\/[^/]+$/.test(path) && !path.includes('..')
    ? path
    : null
}

/** The size the MCP client reported for an answer it would not hand back, as "421,158 characters". */
function sizeOf(answer: McpAnswer): string {
  return /\(([\d,]+ characters)\)/.exec(textOf(answer.content).slice(0, 500))?.[1] ?? 'too many characters'
}

/** The JSON text an MCP tool answered, parsed; throws with the words that came back. */
export function svlOf(answer: McpAnswer): Svl {
  const text = textOf(answer.content)
  if (answer.isError) {
    throw new Error(text.slice(0, 300) || 'Orca returned an error')
  }
  return svlOfText(text)
}

/** An SVL answer's text, parsed; throws with the words when they are not one. */
export function svlOfText(text: string): Svl {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    // Not JSON: an error the server or the MCP client wrote as plain text.
    throw new Error(text.trim().slice(0, 300) || 'Orca returned an empty answer')
  }
  if (!isObject(parsed) || parsed.status !== 'success') {
    throw new Error(`Orca answered: ${text.slice(0, 300)}`)
  }
  return parsed
}

/**
 * One page's rows. An answer too large for the MCP client is read from the file
 * the client saved it to; where that can't be read, the page is fetched again in
 * halves, down to one row. One alert can pass the cap alone: a kernel alert's
 * every open CVE comes to hundreds of thousands of characters.
 */
export async function pagesOf<Row>(
  call: (args: SvlArgs) => Promise<McpAnswer>,
  args: SvlArgs,
  parse: (svl: Svl) => Row[],
  readSaved?: (path: string) => Promise<string>,
): Promise<Row[]> {
  const answer = await call(args)
  if (!tooLarge(answer)) {
    return parse(svlOf(answer))
  }
  const path = savedPathOf(answer)
  if (path !== null && readSaved !== undefined) {
    try {
      return parse(svlOfText(await readSaved(path)))
    } catch {
      // Unreadable or not an answer: fetch it in halves instead.
    }
  }
  if (args.limit > 1) {
    const offset = args.offset ?? 0
    const first = Math.ceil(args.limit / 2)
    const [head, tail] = await Promise.all([
      pagesOf(call, { ...args, limit: first, offset }, parse, readSaved),
      pagesOf(call, { ...args, limit: args.limit - first, offset: offset + first }, parse, readSaved),
    ])
    return [...head, ...tail]
  }
  throw new Error(`Orca's answer for one row is too large to load (${sizeOf(answer)}).`)
}

/** Rows in order with any a later page repeated left out (pages can overlap on equal scores). */
export function uniqueById<Row extends { id: string }>(rows: Row[]): Row[] {
  const seen = new Set<string>()
  return rows.filter(row => {
    if (seen.has(row.id)) {
      return false
    }
    seen.add(row.id)
    return true
  })
}

function riskOf(value: unknown): RiskLevel {
  return RISK_LEVELS.includes(value as RiskLevel) ? (value as RiskLevel) : 'informational'
}

/** Each item of a list answer, with a reader for its `{ Field: { value } }` data. */
function itemsOf(svl: Svl) {
  const items = Array.isArray(svl.data) ? svl.data : []
  return items.flatMap(item => {
    if (!isObject(item) || !isObject(item.data)) {
      return []
    }
    const data = item.data
    const value = (key: string): unknown => {
      const entry = data[key]
      return isObject(entry) ? entry.value : undefined
    }
    const text = (key: string): string | null => {
      const found = value(key)
      return typeof found === 'string' && found !== '' ? found : null
    }
    const score = (): number | null => {
      const found = value('OrcaScore')
      return typeof found === 'number' ? found : null
    }
    return [{ id: typeof item.id === 'string' ? item.id : null, value, text, score }]
  })
}

/** Alert rows from a list answer; a cloud alert names the asset it is on. */
export function alertRowsOf(svl: Svl, section: 'code' | 'cloud'): AlertRow[] {
  return itemsOf(svl).flatMap(({ value, text, score }) => {
    const id = text('AlertId')
    if (id === null) {
      return []
    }
    const asset = value('AssetData')
    const onAsset = (key: string): string | null => {
      const found = isObject(asset) ? asset[key] : undefined
      return typeof found === 'string' && found !== '' ? found : null
    }
    const cloud = section === 'cloud'
    const findings = value('RiskFindings')
    return [
      {
        id,
        title: text('Title') ?? id,
        risk: riskOf(value('RiskLevel')),
        score: score(),
        status: text('Status') ?? 'open',
        kind: cloud ? (onAsset('asset_type') ?? text('Category')) : (text('AppsecScanType') ?? text('Category')),
        where: cloud ? onAsset('asset_name') : (text('FilePath') ?? text('Source')),
        cloud: cloud ? onAsset('cloud_provider') : null,
        category: text('Category'),
        ruleId: text('RuleId'),
        ruleType: text('RuleType'),
        description: text('Description') ?? text('Details'),
        recommendation: text('Recommendation'),
        ...linesOf(findings),
        image: cloud ? onAsset('asset_image_name') : null,
        ...cveOf(findings),
      },
    ]
  })
}

function numberIn(value: unknown, key: string): number | null {
  const found = isObject(value) ? value[key] : undefined
  return typeof found === 'number' ? found : null
}

function stringIn(value: unknown, key: string): string | null {
  const found = isObject(value) ? value[key] : undefined
  return typeof found === 'string' && found !== '' ? found : null
}

/** The lines a code finding points at (RiskFindings.position). */
function linesOf(findings: unknown): { startLine: number | null; endLine: number | null } {
  const position = isObject(findings) ? findings.position : undefined
  const startLine = numberIn(position, 'start_line')
  return { startLine, endLine: numberIn(position, 'end_line') ?? startLine }
}

/**
 * The CVE a vulnerability alert leads with and the package fix it names: a
 * single-CVE alert carries RiskFindings.cve with its packages, a per-package one
 * RiskFindings.top_cves.
 */
function cveOf(findings: unknown): { cve: string | null; fix: string | null } {
  if (!isObject(findings)) {
    return { cve: null, fix: null }
  }
  const tops = Array.isArray(findings.top_cves) ? findings.top_cves : []
  const lead = isObject(findings.cve) ? findings.cve : tops[0]
  const id = stringIn(lead, 'cve_id')
  const cvss = numberIn(lead, 'cvss_score')
  const cve = id === null ? null : cvss === null ? id : `${id} (CVSS ${cvss})`

  const packages = isObject(lead) && Array.isArray(lead.packages) ? lead.packages : []
  const pkg = packages[0]
  const installed = stringIn(pkg, 'installed_version')
  const patched = stringIn(pkg, 'patched_version')
  const rawName = stringIn(pkg, 'package_name')
  if (rawName === null || patched === null) {
    return { cve, fix: null }
  }
  // Orca spells the name with its version: "next-15.2.2".
  const name = installed !== null && rawName.endsWith(`-${installed}`) ? rawName.slice(0, -installed.length - 1) : rawName
  const paths = isObject(pkg) && Array.isArray(pkg.non_os_package_paths) ? pkg.non_os_package_paths : []
  const path = typeof paths[0] === 'string' ? ` (${paths[0]})` : ''
  return { cve, fix: `${name} ${installed ?? '?'} → ${patched}${path}` }
}

/** Asset rows from a list answer. */
export function assetRowsOf(svl: Svl): AssetRow[] {
  return itemsOf(svl).flatMap(({ id, value, text, score }) => {
    const key = id ?? text('AssetUniqueId')
    if (key === null) {
      return []
    }
    const isCrownJewel = value('IsCrownJewel') === true
    return [
      {
        id: key,
        name: text('Name') ?? key,
        risk: riskOf(value('RiskLevel')),
        score: score(),
        kind: text('NewSubCategory') ?? text('Type'),
        internetFacing: value('IsInternetFacing') === true || text('Exposure') === 'public_facing',
        crownJewel: isCrownJewel
          ? (text('UserDefinedCrownJewelReason') ?? text('DetectedCrownJewelReason') ?? 'Crown jewel')
          : null,
        region: text('Region'),
        uid: text('UiUniqueField'),
      },
    ]
  })
}

/** Counts by risk level, and their sum, from a grouped answer; risks the panel doesn't show are dropped. */
export function countsOf(svl: Svl): { counts: Partial<Record<RiskLevel, number>>; total: number } {
  const counts: Partial<Record<RiskLevel, number>> = {}
  let total = 0
  for (const group of Array.isArray(svl.data) ? svl.data : []) {
    if (!isObject(group) || !isObject(group.key) || typeof group.value !== 'number') {
      continue
    }
    const risk = riskOf(group.key.RiskLevel)
    if (!SHOWN_RISKS.includes(risk)) {
      continue
    }
    counts[risk] = (counts[risk] ?? 0) + group.value
    total += group.value
  }
  return { counts, total }
}

/** The total of a counts answer over every risk. */
export function everyRiskTotalOf(svl: Svl): number {
  let total = 0
  for (const group of Array.isArray(svl.data) ? svl.data : []) {
    if (isObject(group) && typeof group.value === 'number') {
      total += group.value
    }
  }
  return total
}

export type AlertGroup = { key: string; title: string; risk: RiskLevel; score: number | null; alerts: AlertRow[] }

/** A short, stable key for a text: djb2, in base 36. */
export function hashOf(text: string): string {
  let hash = 5381
  for (let i = 0; i < text.length; i++) {
    hash = ((hash << 5) + hash + text.charCodeAt(i)) | 0
  }
  return (hash >>> 0).toString(36)
}

/** Alerts that share a title, in the order of their best score (rows come sorted by score). */
export function groupsOf(alerts: AlertRow[]): AlertGroup[] {
  const groups = new Map<string, AlertGroup>()
  for (const alert of alerts) {
    const found = groups.get(alert.title)
    if (found === undefined) {
      groups.set(alert.title, {
        key: hashOf(alert.title),
        title: alert.title,
        risk: alert.risk,
        score: alert.score,
        alerts: [alert],
      })
    } else {
      found.alerts.push(alert)
    }
  }
  return [...groups.values()]
}

/**
 * Where an alert is, short enough for one line of a side panel: the file and
 * line (with its two nearest folders) for code, the asset for cloud.
 *   main   "ProfileZipSlip.java:79"
 *   detail "lessons/pathtraversal · SAST"
 */
export function locationOf(alert: AlertRow, section: 'code' | 'cloud'): { main: string; detail: string } {
  const progress = alert.status === 'in_progress' ? 'in progress' : null
  if (section === 'cloud') {
    return {
      main: alert.where ?? alert.id,
      detail: [alert.kind, alert.cloud?.toUpperCase(), progress].filter(Boolean).join(' · '),
    }
  }
  const parts = (alert.where ?? '').split('/').filter(Boolean)
  const file = parts.at(-1)
  if (file === undefined) {
    return { main: alert.id, detail: [alert.kind, progress].filter(Boolean).join(' · ') }
  }
  const line = alert.startLine === null || /:\d+$/.test(file) ? '' : `:${alert.startLine}`
  const folders = parts.slice(-3, -1).join('/')
  return {
    main: `${file}${line}`,
    detail: [folders || null, alert.kind, progress].filter(Boolean).join(' · '),
  }
}

export type AssetGroup = { key: string; name: string; assets: AssetRow[] }

/**
 * Assets that share a name (the same container on several nodes, say) are one
 * group, in the order of their best score (rows come sorted by score).
 */
export function assetGroupsOf(assets: AssetRow[]): AssetGroup[] {
  const groups = new Map<string, AssetGroup>()
  for (const asset of assets) {
    const found = groups.get(asset.name)
    if (found === undefined) {
      groups.set(asset.name, { key: hashOf(asset.name), name: asset.name, assets: [asset] })
    } else {
      found.assets.push(asset)
    }
  }
  return [...groups.values()]
}

/** 1234567 -> "1,234,567". */
export function countText(n: number): string {
  return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ',')
}

export function scoreText(score: number | null): string {
  return score === null ? '–' : score.toFixed(1)
}
