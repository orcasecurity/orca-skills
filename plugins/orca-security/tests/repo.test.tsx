import { describe, expect, mock, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import type { On } from 'claude-code'

import { BAR_WIDTH, barSegments, DIVIDER, RISK_COLOR, riskPill, SCORE_WIDTH, severityBar } from '../hooks/repo/marks'
import { actionOf, alertPrompt, approachOf } from '../hooks/repo/prompts'
import type { AlertRow } from '../types'
import {
  alertRowsOf,
  assetGroupsOf,
  assetRowsOf,
  countsCall,
  countsOf,
  everyRiskCall,
  groupsOf,
  hashOf,
  listCalls,
  locationOf,
  pagesOf,
  repoNameOf,
  sectionQuery,
} from '../hooks/repo/queries'
import type { SvlArgs } from '../hooks/repo/queries'

const REPO = 'acme-corp/storefront'
const SQLI = 'SQL Injection Vulnerability Due to Dynamic Query Generation'
const RCE = 'Critical Remote Code Execution Vulnerabilities found in React Server Components and Next.js'
const ZIP_SLIP = 'src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java'

// What the MCP client answers in place of a result past its output cap.
const TOO_LARGE =
  'Error: result (211,335 characters) exceeds maximum allowed tokens. Output has been saved to /tmp/x.txt.'

const sqli = (id: string, file: string, status = 'open') => ({
  id: `x_${id}`,
  type: 'Alert',
  data: {
    AlertId: { value: id },
    Title: { value: SQLI },
    RiskLevel: { value: 'high' },
    OrcaScore: { value: 8.3 },
    Status: { value: status },
    AppsecScanType: { value: 'SAST' },
    FilePath: { value: file },
  },
})

// Shaped like run_svl_query answers, trimmed; every name and id is made up.
const CODE_LIST = {
  status: 'success',
  data: [
    {
      id: 'x_orca-100001',
      type: 'Alert',
      data: {
        AlertId: { value: 'orca-100001' },
        Title: { value: 'User Input Can Control File Paths Leading to Directory Traversal' },
        RiskLevel: { value: 'high' },
        OrcaScore: { value: 8.6 },
        Status: { value: 'open' },
        AppsecScanType: { value: 'SAST' },
        Category: { value: 'Source code vulnerabilities' },
        FilePath: { value: ZIP_SLIP },
        RuleId: { value: 'r0000000001' },
        RuleType: { value: 'shiftleft_00000000-0000-0000-0000-000000000000' },
        Description: { value: 'User input is being used to control a file path.' },
        Recommendation: { value: 'Sanitize user-controlled variables in file paths.' },
        RiskFindings: { value: { position: { start_line: 79, end_line: 79, start_column: 18, end_column: 65 } } },
      },
    },
    sqli('orca-100002', 'src/main/java/org/owasp/webgoat/container/users/UserService.java', 'in_progress'),
    sqli('orca-100003', 'src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson3.java'),
    sqli('orca-100004', 'src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5.java'),
    sqli('orca-100005', 'src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java'),
  ],
}

const CLOUD_LIST = {
  status: 'success',
  data: [
    {
      id: 'x_orca-100006',
      type: 'Alert',
      data: {
        AlertId: { value: 'orca-100006' },
        Title: { value: RCE },
        RiskLevel: { value: 'critical' },
        OrcaScore: { value: 9.4 },
        Status: { value: 'open' },
        Category: { value: 'Vulnerabilities' },
        RuleId: { value: 'r0000000002' },
        RuleType: { value: 'vulnerability' },
        Recommendation: { value: 'Patch the listed packages' },
        Description: { value: 'The following vulnerabilities were found on software: next 15.2.2' },
        AssetData: {
          value: {
            asset_name: 'shop-eks-cluster-checkout-app',
            asset_type: 'Container',
            cloud_provider: 'aws',
            asset_image_name: '123456789012.dkr.ecr.us-east-1.amazonaws.com/storefront',
          },
        },
        RiskFindings: {
          value: {
            cve: {
              cve_id: 'CVE-2025-55182',
              cvss_score: 10,
              packages: [
                {
                  package_name: 'next-15.2.2',
                  installed_version: '15.2.2',
                  patched_version: '15.2.6',
                  non_os_package_paths: ['/app/package-lock.json', '/app/node_modules/next/package.json'],
                },
              ],
            },
          },
        },
      },
    },
    {
      id: 'x_orca-100007',
      type: 'Alert',
      data: {
        AlertId: { value: 'orca-100007' },
        Title: { value: 'EC2 Instance Querying a Command and Control Domain' },
        RiskLevel: { value: 'high' },
        OrcaScore: { value: 8.2 },
        Status: { value: 'open' },
        Category: { value: 'Suspicious activity' },
        AssetData: { value: { asset_name: 'shop-eks-node-1', asset_type: 'VM', cloud_provider: 'aws' } },
      },
    },
  ],
}

const container = (id: string, uid: string) => ({
  id,
  type: 'Container',
  data: {
    Name: { value: 'checkout-app' },
    RiskLevel: { value: 'critical' },
    OrcaScore: { value: 9.5 },
    NewSubCategory: { value: 'Containers' },
    Exposure: { value: 'public_facing' },
    IsInternetFacing: { value: true },
    IsCrownJewel: { value: true },
    DetectedCrownJewelReason: { value: 'Sensitive Data' },
    Region: { value: 'us-east-1' },
    UiUniqueField: { value: uid },
  },
})

const ASSET_LIST = {
  status: 'success',
  data: [
    container('00000000-0000-4000-8000-000000000001', 'i-0123456789abcdef0_000000000001'),
    // The same container on another node: same name, its own asset.
    container('00000000-0000-4000-8000-000000000002', 'i-0123456789abcdef1_000000000002'),
    {
      id: '00000000-0000-4000-8000-000000000003',
      type: 'VM',
      data: {
        Name: { value: 'mongodb-instance' },
        RiskLevel: { value: 'high' },
        OrcaScore: { value: 8.9 },
        NewSubCategory: { value: 'Virtual Instances' },
        IsInternetFacing: { value: true },
        IsCrownJewel: { value: false },
        Region: { value: 'us-east-1' },
      },
    },
  ],
}

const grouped = (counts: Record<string, number>) => ({
  status: 'success',
  data: Object.entries(counts).map(([RiskLevel, value]) => ({ key: { RiskLevel }, value, aggregations: {} })),
})
const CODE_COUNTS = grouped({ high: 81, medium: 227, low: 206, informational: 184 })
const CLOUD_COUNTS = grouped({ critical: 2, high: 14, medium: 94, low: 456, informational: 400 })
const ASSET_COUNTS = grouped({ critical: 4, high: 8, medium: 6, low: 11, informational: 33 })

const RUN = {
  origin: { kind: 'composer' },
  presentation: { isFullscreen: true, columns: 120 },
} as const

const PANE = {
  plugin: 'orca-security',
  component: 'Pane',
  requestId: 'orca-repo',
  props: {
    title: 'Orca Security',
    isFocused: false,
    bodyColumns: 48,
    placement: 'dock',
    scroll: { offset: 0, bodyRows: 80 },
    view: {},
  },
} as const

type Section = 'code' | 'cloud' | 'assets'
type Asked = { server: unknown; tool: unknown; section: Section; args: Record<string, unknown> }

function sectionOf(query: unknown): Section {
  const text = JSON.stringify(query)
  return text.startsWith('{"type":"object_set","models":["Inventory"]') ? 'assets' : text.includes('CodeOrigins') ? 'cloud' : 'code'
}

const isList = (call: Asked) => !('group_by' in call.args)
/** A count over every risk: the query names no RiskLevel. */
const isEveryRisk = (call: Asked) => !isList(call) && !JSON.stringify(call.args.query).includes('"key":"RiskLevel"')
const NOTHING = { status: 'success', data: [], total_items: 0 }

type Overrides = Partial<Record<Section, unknown>>

/**
 * The engine beneath the plugin: a repo with an origin, and an Orca server.
 * `codeListText`, when given, is what every code list call answers; `answers`
 * replaces a section's counts, every-risk counts or list.
 */
function world(
  on: On,
  remote: string | null,
  codeListText?: string,
  answers: { counts?: Overrides; everyRisk?: Overrides; lists?: Overrides } = {},
) {
  mock.clock(on, { now: 1_800_000_000_000 })
  const asked: Asked[] = []
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('command.register', () => ({ value: { command: 'orca' } }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('session.repo', () => ({
    value: remote === null ? null : { root: '/repo', remote, internal: false, name: null },
  }))
  on('tool.list', () => ({
    value: [{ name: 'mcp__claude_ai_Orca__run_svl_query', description: 'Run an SVL query', mcp: true }],
  }))
  on('mcp.call', (_, e) => {
    const section = sectionOf(e.args.query)
    const call = { server: e.server, tool: e.tool, section, args: e.args }
    asked.push(call)
    const counts =
      (isEveryRisk(call) ? answers.everyRisk?.[section] : undefined) ??
      answers.counts?.[section] ??
      { code: CODE_COUNTS, cloud: CLOUD_COUNTS, assets: ASSET_COUNTS }[section]
    const list = answers.lists?.[section] ?? { code: CODE_LIST, cloud: CLOUD_LIST, assets: ASSET_LIST }[section]
    const text =
      'group_by' in e.args ? JSON.stringify(counts) : section === 'code' && codeListText ? codeListText : JSON.stringify(list)
    return { value: { content: [{ type: 'text', text }], isError: false } }
  })
  return asked
}

async function opened($: Engine, args = '') {
  await $.session.start({ cwd: '/repo', surface: 'desktop', isInteractive: true })
  await $.command.run({ ...RUN, command: 'orca', args })
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  await ui.press({ key: 'refresh' })
  return ui
}

describe('the repository and its queries', () => {
  test('names the repository from any origin form', () => {
    expect(repoNameOf('https://github.com/example-org/web-app.git')).toBe('example-org/web-app')
    expect(repoNameOf(`git@github.com:${REPO}.git`)).toBe(REPO)
    expect(repoNameOf('ssh://git@gitlab.com:22/team/sub/app.git')).toBe('team/sub/app')
    expect(repoNameOf(null)).toBe(null)
    expect(repoNameOf('not a remote')).toBe(null)
  })

  test('each tab asks for its own slice of Orca', () => {
    const code = JSON.stringify(sectionQuery('code', REPO))
    expect(code).toContain('"Code Repository"')
    expect(code).toContain(REPO)
    expect(code).not.toContain('CodeOrigins')

    const cloud = JSON.stringify(sectionQuery('cloud', REPO))
    expect(cloud).toContain('"models":["Alert"]')
    expect(cloud).toContain('"keys":["CodeOrigins"]')
    expect(cloud).toContain('"open","in_progress"')

    // The Inventory query as the Orca UI runs it, for the risks the panel shows.
    expect(sectionQuery('assets', REPO)).toEqual({
      type: 'object_set',
      models: ['Inventory'],
      with: {
        type: 'operation',
        operator: 'and',
        values: [
          {
            type: 'object_set',
            models: ['CodeOrigin'],
            keys: ['CodeOrigins'],
            operator: 'has',
            with: {
              type: 'object',
              models: ['CodeRepository'],
              keys: ['CodeRepository'],
              operator: 'has',
              with: { type: 'str', key: 'Name', operator: 'in', values: [REPO] },
            },
          },
          { type: 'str', key: 'RiskLevel', operator: 'in', values: ['critical', 'high', 'medium'] },
        ],
      },
    })
  })

  test('the every-risk count is the same slice with no risk named', () => {
    for (const section of ['cloud', 'assets'] as const) {
      const every = JSON.stringify(everyRiskCall(section, REPO).query)
      expect(every).not.toContain('RiskLevel')
      expect(every).toContain(REPO)
      expect(every).toContain('CodeOrigins')
    }
    expect(everyRiskCall('assets', REPO).group_by).toEqual(['RiskLevel'])
  })

  test('low and informational are never asked for', () => {
    const shown = '"key":"RiskLevel","operator":"in","values":["critical","high","medium"]'
    for (const section of ['code', 'cloud', 'assets'] as const) {
      for (const query of [countsCall(section, REPO).query, listCalls(section, REPO, 'all')[0]?.query]) {
        expect(JSON.stringify(query)).toContain(shown)
        expect(JSON.stringify(query)).not.toMatch(/"low"|"informational"/)
      }
      // A chosen risk narrows the list; counts keep every shown risk.
      expect(JSON.stringify(listCalls(section, REPO, 'high')[0]?.query)).toContain('"key":"RiskLevel","operator":"in","values":["high"]')
      // A hidden risk chosen before reads as all.
      expect(JSON.stringify(listCalls(section, REPO, 'low')[0]?.query)).toContain(shown)
    }
    // Counts drop them even where an answer carries them.
    expect(countsOf(CODE_COUNTS)).toEqual({ counts: { high: 81, medium: 227 }, total: 308 })
  })

  test('lists are asked for in small pages that cover the shown rows once', () => {
    expect(listCalls('code', REPO, 'all').map(page => [page.offset, page.limit])).toEqual([
      [0, 5],
      [5, 5],
      [10, 5],
      [15, 5],
      [20, 5],
    ])
    expect(listCalls('assets', REPO, 'all', 7).map(page => page.limit)).toEqual([5, 2])
  })

  test('a page too large for the MCP client is asked for again in halves', async () => {
    const asked: Array<[number, number]> = []
    const call = async (args: SvlArgs) => {
      asked.push([args.offset ?? 0, args.limit])
      const text = args.limit > 2 ? TOO_LARGE : JSON.stringify(CODE_LIST)
      return { content: [{ type: 'text', text }], isError: false }
    }
    const rows = await pagesOf(call, listCalls('code', REPO, 'all')[2] as SvlArgs, svl => alertRowsOf(svl, 'code'))
    // 5 at 10 is too large -> 3 at 10 (too large -> 2 at 10, 1 at 12) and 2 at 13.
    expect([...asked].sort((a, b) => a[0] - b[0] || b[1] - a[1])).toEqual([
      [10, 5],
      [10, 3],
      [10, 2],
      [12, 1],
      [13, 2],
    ])
    expect(rows.length).toBe(15)
  })

  test('an answer too large for the MCP client is read from the file it was saved to', async () => {
    const saved = '/Users/me/.claude/projects/-Users-me-repo/abc12345/tool-results/mcp-orca-run_svl_query-1794765626807.txt'
    const asked: SvlArgs[] = []
    const read: string[] = []
    const call = async (args: SvlArgs) => {
      asked.push(args)
      const text = `Error: result (421,158 characters) exceeds maximum allowed tokens. Output has been saved to ${saved}.`
      return { content: [{ type: 'text', text }], isError: false }
    }
    const readSaved = async (path: string) => {
      read.push(path)
      return JSON.stringify(CODE_LIST)
    }
    const rows = await pagesOf(call, listCalls('code', REPO, 'all')[0] as SvlArgs, svl => alertRowsOf(svl, 'code'), readSaved)
    expect(read).toEqual([saved])
    expect(asked.length).toBe(1)
    expect(rows.length).toBe(5)
  })

  test('a saved answer is read only from a tool-results folder, and one row past the cap says so', async () => {
    const read: string[] = []
    const readSaved = async (path: string) => {
      read.push(path)
      return JSON.stringify(CODE_LIST)
    }
    // TOO_LARGE names /tmp/x.txt: not a tool-results file, so never read.
    const call = async () => ({ content: [{ type: 'text', text: TOO_LARGE }], isError: false })
    const one = { ...(listCalls('code', REPO, 'all')[0] as SvlArgs), limit: 1 }
    await expect(pagesOf(call, one, svl => alertRowsOf(svl, 'code'), readSaved)).rejects.toThrow(
      "Orca's answer for one row is too large to load (211,335 characters).",
    )
    expect(read).toEqual([])
  })

  test('reads where an alert is and what fixes it', () => {
    expect(alertRowsOf(CODE_LIST, 'code')[0]).toMatchObject({
      where: ZIP_SLIP,
      kind: 'SAST',
      ruleId: 'r0000000001',
      startLine: 79,
      endLine: 79,
      recommendation: 'Sanitize user-controlled variables in file paths.',
      cve: null,
      fix: null,
    })
    expect(alertRowsOf(CLOUD_LIST, 'cloud')[0]).toMatchObject({
      where: 'shop-eks-cluster-checkout-app',
      kind: 'Container',
      cloud: 'aws',
      image: '123456789012.dkr.ecr.us-east-1.amazonaws.com/storefront',
      cve: 'CVE-2025-55182 (CVSS 10)',
      fix: 'next 15.2.2 → 15.2.6 (/app/package-lock.json)',
    })
    expect(countsOf(CLOUD_COUNTS).total).toBe(110)
  })

  test('says where an alert is in one short line', () => {
    const [zip, inProgress] = alertRowsOf(CODE_LIST, 'code')
    expect(locationOf(zip!, 'code')).toEqual({ main: 'ProfileZipSlip.java:79', detail: 'lessons/pathtraversal · SAST' })
    expect(locationOf(inProgress!, 'code')).toEqual({ main: 'UserService.java', detail: 'container/users · SAST · in progress' })
    expect(locationOf(alertRowsOf(CLOUD_LIST, 'cloud')[0]!, 'cloud')).toEqual({
      main: 'shop-eks-cluster-checkout-app',
      detail: 'Container · AWS',
    })
  })

  test('groups alerts by title and assets by name', () => {
    expect(groupsOf(alertRowsOf(CODE_LIST, 'code')).map(group => [group.title, group.alerts.length])).toEqual([
      ['User Input Can Control File Paths Leading to Directory Traversal', 1],
      [SQLI, 4],
    ])
    const assets = assetRowsOf(ASSET_LIST)
    expect(assets[0]).toMatchObject({ crownJewel: 'Sensitive Data', uid: 'i-0123456789abcdef0_000000000001' })
    expect(assetGroupsOf(assets).map(group => [group.name, group.assets.length])).toEqual([
      ['checkout-app', 2],
      ['mongodb-instance', 1],
    ])
  })
})

describe('acting on an alert, by its kind', () => {
  /** A row as alertRowsOf makes one, with only what a case sets. */
  const row = (fields: Partial<AlertRow>): AlertRow => ({
    id: 'orca-1',
    title: 'An alert',
    risk: 'high',
    score: 7,
    status: 'open',
    kind: null,
    where: null,
    cloud: null,
    category: null,
    ruleId: null,
    ruleType: null,
    description: null,
    recommendation: null,
    startLine: null,
    endLine: null,
    image: null,
    cve: null,
    fix: null,
    ...fields,
  })

  test('each kind of alert gets its own button', () => {
    const cases: Array<[Partial<AlertRow>, 'code' | 'cloud', string, string]> = [
      [{ kind: 'SAST', category: 'Source code vulnerabilities' }, 'code', 'code', 'Fix'],
      [{ kind: 'IaC', category: 'Network misconfigurations' }, 'code', 'iac', 'Fix'],
      [{ kind: 'Vulnerabilities', category: 'Vulnerabilities' }, 'code', 'dependency', 'Fix'],
      [{ kind: 'Secret Detection', category: 'Data at risk' }, 'code', 'secret', 'Fix'],
      [{ kind: 'OSS License', category: 'Best practices' }, 'code', 'license', 'Review'],
      [{ kind: 'SCM Posture', category: 'Best practices' }, 'code', 'scm', 'Review'],
      [{ kind: 'Container', category: 'Vulnerabilities' }, 'cloud', 'dependency', 'Fix'],
      [{ kind: 'VM', category: 'Workload misconfigurations' }, 'cloud', 'cloud-config', 'Fix'],
      [{ kind: 'Role', category: 'IAM misconfigurations' }, 'cloud', 'cloud-config', 'Fix'],
      [{ kind: 'VM', category: 'Suspicious activity' }, 'cloud', 'runtime', 'Investigate'],
      [{ kind: 'Database', category: 'Data at risk' }, 'cloud', 'runtime', 'Investigate'],
      [{ kind: 'VM', category: 'Malware' }, 'cloud', 'runtime', 'Investigate'],
    ]
    for (const [fields, section, approach, action] of cases) {
      expect([fields.kind, fields.category, approachOf(row(fields), section)]).toEqual([fields.kind, fields.category, approach])
      expect(actionOf(approachOf(row(fields), section))).toBe(action)
    }
  })

  test('a SAST alert names its file and lines and keeps dependencies as they are', () => {
    const prompt = alertPrompt(alertRowsOf(CODE_LIST, 'code')[0]!, 'code', REPO)
    expect(prompt.split('\n').slice(0, 7)).toEqual([
      'Fix the following security alert:',
      'Alert Name: User Input Can Control File Paths Leading to Directory Traversal',
      'Alert ID: orca-100001 (https://app.orcasecurity.io/alerts/orca-100001)',
      `Path: ${ZIP_SLIP}#L79`,
      `Asset: ${REPO}`,
      'Type: SAST · Source code vulnerabilities',
      'Rule ID: r0000000001',
    ])
    expect(prompt).toContain('Remediation Guidance: Sanitize user-controlled variables in file paths.')
    expect(prompt).toContain('Description:\nUser input is being used to control a file path.')
    expect(prompt).toContain('Review the affected code and make a minimal, targeted fix')
    expect(prompt).toContain('- Do not change dependencies or package versions.')
    expect(prompt).not.toContain('vulnerability')
  })

  test('a vulnerable package in a deployed image is upgraded where the repository pins it', () => {
    const prompt = alertPrompt(alertRowsOf(CLOUD_LIST, 'cloud')[0]!, 'cloud', REPO)
    expect(prompt).toContain(
      'Asset: shop-eks-cluster-checkout-app · Container · AWS · image 123456789012.dkr.ecr.us-east-1.amazonaws.com/storefront',
    )
    expect(prompt).toContain('Type: Vulnerabilities')
    expect(prompt).toContain('Package: next 15.2.2 → 15.2.6 (/app/package-lock.json)')
    expect(prompt).toContain('Top CVE: CVE-2025-55182 (CVSS 10)')
    expect(prompt).toContain('upgrade it to the nearest version that fixes it')
    expect(prompt).toContain('- Upgrade only the affected package; leave other dependencies as they are.')
    expect(prompt).not.toContain('Path:')
  })

  test('an IaC misconfiguration is fixed in its file, a cloud one in the IaC that defines the asset', () => {
    const iac = alertPrompt(row({ kind: 'IaC', category: 'Network misconfigurations', where: 'terraform/sg.tf', startLine: 12, endLine: 18 }), 'code', REPO)
    expect(iac).toContain('Path: terraform/sg.tf#L12-L18')
    expect(iac).toContain('Change the configuration in that file so the check passes')

    const cloud = alertPrompt(row({ kind: 'VM', category: 'Workload misconfigurations', where: 'web-1' }), 'cloud', REPO)
    expect(cloud.split('\n')[0]).toBe('Fix the following security alert:')
    expect(cloud).toContain(`The asset is deployed from ${REPO}: find where the repository defines it`)
    expect(cloud).toContain('give the console or CLI change instead of editing code')
  })

  test('a secret is taken out of the code and flagged for rotation', () => {
    const prompt = alertPrompt(row({ kind: 'Secret Detection', category: 'Data at risk', where: 'config/app.yml' }), 'code', REPO)
    expect(prompt).toContain('Remove the secret from the code')
    expect(prompt).toContain('it has to be rotated')
  })

  test('license and repository-setting findings ask for a review and change nothing', () => {
    for (const kind of ['OSS License', 'SCM Posture']) {
      const prompt = alertPrompt(row({ kind, category: 'Best practices' }), 'code', REPO)
      expect(prompt.split('\n')[0]).toBe('Review the following Orca alert:')
      expect(prompt).toMatch(/Don’t change (anything|any settings)/)
      expect(prompt).not.toContain('- Only change what this alert is about')
    }
  })

  test('a runtime detection asks for an investigation, not a patch', () => {
    const prompt = alertPrompt(alertRowsOf(CLOUD_LIST, 'cloud')[1]!, 'cloud', REPO)
    expect(prompt.split('\n')[0]).toBe('Investigate the following Orca alert:')
    expect(prompt).toContain('Type: Suspicious activity')
    expect(prompt).toContain('This is a detection on a running cloud asset, not a code finding.')
    expect(prompt).not.toContain('Fix the following')
    expect(prompt).not.toContain('- Do not change dependencies')
  })
})

test('the panel opens on Code, listing only that tab', async ($, on) => {
  const asked = world(on, `git@github.com:${REPO}.git`)
  const ui = await opened($)

  expect(await ui.find({ type: 'Text', text: REPO })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: /418 open alerts · 18 assets/ })).toBeDefined()
  for (const [section, label] of [
    ['code', 'Code 308'],
    ['cloud', 'Cloud 110'],
    ['assets', 'Assets 18'],
  ]) {
    expect(await ui.find({ key: `tab-${section}`, text: label })).toBeDefined()
  }
  // Risk chips for what the panel shows; Orca's low and info counts are dropped.
  expect(await ui.find({ key: 'filter-high' })).toBeDefined()
  expect(await ui.find({ key: 'filter-medium' })).toBeDefined()
  expect(await ui.find({ key: 'filter-low' })).toBeUndefined()
  expect(await ui.find({ key: 'filter-informational' })).toBeUndefined()
  expect(asked.filter(isList).every(call => call.section === 'code' && (call.args.limit as number) <= 5)).toBe(true)
  // Opening refreshes and so does the test's press: counts for every tab each time.
  expect([...new Set(asked.filter(call => !isList(call)).map(call => call.section))].sort()).toEqual(['assets', 'cloud', 'code'])
  expect(asked[0]?.server).toBe('claude_ai_Orca')
  // Every tab has something to show, so nothing more is asked.
  expect(asked.some(isEveryRisk)).toBe(false)
  await ui.unmount()
})

test('Cloud and Assets say when Orca traces nothing to the repository', async ($, on) => {
  const asked = world(on, `git@github.com:${REPO}.git`, undefined, {
    counts: { cloud: grouped({}), assets: grouped({}) },
    everyRisk: { assets: grouped({}) },
    lists: { cloud: NOTHING, assets: NOTHING },
  })
  const ui = await opened($)

  for (const section of ['cloud', 'assets']) {
    await ui.press({ key: `tab-${section}` })
    expect(await ui.find({ type: 'Text', text: /Orca hasn't traced any cloud assets to this repository \(no Code Origin links\)/ })).toBeDefined()
  }
  // Nothing linked, so the cloud alerts are not counted again.
  expect([...new Set(asked.filter(isEveryRisk).map(call => call.section))]).toEqual(['assets'])
  await ui.unmount()
})

test('Cloud and Assets say when what is linked is only low or informational', async ($, on) => {
  world(on, `git@github.com:${REPO}.git`, undefined, {
    counts: { cloud: grouped({ low: 5, informational: 2 }), assets: grouped({ low: 3, informational: 1 }) },
    everyRisk: { cloud: grouped({ low: 5, informational: 2 }), assets: grouped({ low: 3, informational: 1 }) },
    lists: { cloud: NOTHING, assets: NOTHING },
  })
  const ui = await opened($)

  await ui.press({ key: 'tab-assets' })
  expect(await ui.find({ type: 'Text', text: '4 cloud assets are deployed from this repository, none critical, high or medium.' })).toBeDefined()
  await ui.press({ key: 'tab-cloud' })
  expect(
    await ui.find({ type: 'Text', text: '7 open alerts on cloud assets deployed from this repository, none critical, high or medium.' }),
  ).toBeDefined()
  await ui.unmount()
})

test('Cloud says when the linked assets have no open alerts', async ($, on) => {
  world(on, `git@github.com:${REPO}.git`, undefined, {
    counts: { cloud: grouped({}) },
    everyRisk: { cloud: grouped({}) },
    lists: { cloud: NOTHING },
  })
  const ui = await opened($)
  await ui.press({ key: 'tab-cloud' })
  expect(await ui.find({ type: 'Text', text: 'No open alerts on the cloud assets deployed from this repository.' })).toBeDefined()
  await ui.unmount()
})

describe("the panel's pictures", () => {
  test("a risk badge is the platform's filled badge", () => {
    const pill = riskPill('critical', '9.8', SCORE_WIDTH)
    expect(pill).toContain(`fill="${RISK_COLOR.critical}"`)
    expect(pill).toContain('rx="4"')
    expect(pill).toContain('>9.8</text>')
    expect(pill).toContain(`width="${SCORE_WIDTH}"`)
    expect(riskPill('high', '<1>')).toContain('&lt;1&gt;')
  })

  test('the risk bar spans the panel, critical first, a small risk still seen', () => {
    const segments = barSegments({ critical: 2, high: 14, medium: 94, low: 500 }, ['critical', 'high', 'medium'])
    expect(segments?.map(s => s.risk)).toEqual(['critical', 'high', 'medium'])
    expect(segments?.[0]?.width).toBe(80)
    const last = segments?.[segments.length - 1]
    expect((last?.x ?? 0) + (last?.width ?? 0)).toBe(BAR_WIDTH)
    expect(barSegments({ high: 3 }, ['critical', 'high', 'medium'])).toEqual([{ risk: 'high', x: 0, width: BAR_WIDTH }])
    // Scaled evenly to the panel's width: its own viewBox, and no height of the panel's.
    expect(severityBar({ high: 3 }, ['high'])).toContain(`viewBox="0 0 ${BAR_WIDTH} 60"`)
    expect(severityBar({}, ['critical', 'high', 'medium'])).toBe(null)
  })
})

test('on the desktop, scores are badges, a tab its risk bar, entries lit under the pointer', async ($, on) => {
  world(on, `git@github.com:${REPO}.git`)
  const ui = await opened($)

  const pictures = await ui.findAll({ type: 'Svg' })
  const alts = pictures.map(p => p.props.alt)
  expect(alts).toContain('Risk mix: 81 high, 227 medium')
  expect(alts).toContain('High risk, Orca score 8.3')
  // Two entries on Code (ZipSlip, the SQL injections), one hairline between them.
  expect(alts.filter(alt => alt === 'separator')).toHaveLength(1)
  expect(pictures.find(p => p.props.alt === 'separator')?.props.source).toBe(DIVIDER)
  const scores = pictures.filter(p => String(p.props.alt).includes('Orca score'))
  expect(scores.length).toBe(2)
  expect(scores.every(p => p.props.width === SCORE_WIDTH)).toBe(true)

  // Set in a little, where the pointer lights it (the kit keeps `hover` to the surface).
  expect((await ui.find({ key: `group-code:${hashOf(SQLI)}` }))?.props.paddingX).toBe('sm')
  expect(await ui.find({ type: 'Text', text: /ProfileZipSlip\.java:79/ })).toBeDefined()
  await ui.unmount()
})

test('the terminal, with no Svg, draws text badges and no pictures', async ($, on) => {
  world(on, `git@github.com:${REPO}.git`)
  await $.session.start({ cwd: '/repo', surface: 'terminal', isInteractive: true })
  await $.command.run({ ...RUN, command: 'orca', args: '' })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await ui.press({ key: 'refresh' })

  expect(await ui.findAll({ type: 'Svg' })).toHaveLength(0)
  expect(await ui.find({ type: 'Text', text: ' 8.3 ' })).toBeDefined()
  expect((await ui.find({ key: `group-code:${hashOf(SQLI)}` }))?.props.paddingX).toBeUndefined()
  await ui.unmount()
})

test('every alert shows where it is with Fix and Open, no click needed', async ($, on) => {
  world(on, `git@github.com:${REPO}.git`)
  // Fix sends the prompt as the person's own words, without the plugin's frame.
  const sent: Array<{ text: string; asUser?: boolean }> = []
  on('prompt.submit', (_, e) => {
    sent.push({ text: e.text, asUser: e.origin.kind === 'plugin' ? e.origin.asUser : undefined })
    return { text: e.text }
  })
  const ui = await opened($)

  expect(await ui.find({ type: 'Text', text: /ProfileZipSlip\.java:79/ })).toBeDefined()
  expect(await ui.find({ key: 'act-orca-100001' })).toBeDefined()
  expect(await ui.findAll({ type: 'Link', text: 'Open' })).toHaveLength(4)

  await ui.press({ key: 'act-orca-100001' })
  expect(sent[0]?.text.startsWith('Fix the following security alert:')).toBe(true)
  expect(sent[0]?.asUser).toBe(true)

  // A group lists its first three places, the rest behind "+1 more".
  for (const id of ['orca-100002', 'orca-100003', 'orca-100004']) {
    expect(await ui.find({ key: `act-${id}` })).toBeDefined()
  }
  expect(await ui.find({ key: 'act-orca-100005' })).toBeUndefined()
  const more = `more-code:${hashOf(SQLI)}`
  expect(await ui.find({ key: more, text: '+1 more' })).toBeDefined()
  await ui.press({ key: more })
  expect(await ui.find({ key: 'act-orca-100005' })).toBeDefined()
  expect(await ui.find({ key: more, text: 'Show fewer' })).toBeDefined()
  await ui.unmount()
})

test('the Cloud and Assets tabs list what the repository deploys', async ($, on) => {
  const asked = world(on, `git@github.com:${REPO}.git`)
  const ui = await opened($)

  await ui.press({ key: 'tab-cloud' })
  expect(asked.filter(isList).some(call => call.section === 'cloud')).toBe(true)
  expect(await ui.find({ type: 'Text', text: RCE })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: /shop-eks-cluster-checkout-app {2}Container · AWS/ })).toBeDefined()
  expect(await ui.find({ key: 'act-orca-100006', text: 'Fix' })).toBeDefined()
  expect(await ui.find({ key: 'act-orca-100007', text: 'Investigate' })).toBeDefined()

  await ui.press({ key: 'tab-assets' })
  expect(await ui.find({ key: 'profile-00000000-0000-4000-8000-000000000003' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: /checkout-app {2}×2/ })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: /♛ Crown jewel · Sensitive Data/ })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'Containers · internet-facing · us-east-1' })).toBeDefined()
  expect(await ui.find({ key: 'profile-00000000-0000-4000-8000-000000000001' })).toBeDefined()
  expect(await ui.find({ key: 'profile-00000000-0000-4000-8000-000000000002' })).toBeDefined()

  // Back on Code, nothing loads again.
  const before = asked.length
  await ui.press({ key: 'tab-code' })
  expect(asked.length).toBe(before)
  await ui.unmount()
})

test('choosing a risk reloads the tab on show for that risk alone', async ($, on) => {
  const asked = world(on, `git@github.com:${REPO}.git`)
  const ui = await opened($)
  asked.length = 0

  await ui.press({ key: 'filter-high' })
  const lists = asked.filter(isList)
  expect(lists.length).toBe(5)
  expect(lists.every(call => call.section === 'code' && JSON.stringify(call.args.query).includes('"values":["high"]'))).toBe(true)
  expect(await ui.find({ type: 'Text', text: /Showing the top 5 of 81 high by Orca score/ })).toBeDefined()

  // The same risk again clears it, back to every risk the panel shows.
  asked.length = 0
  await ui.press({ key: 'filter-high' })
  const cleared = asked.filter(isList)
  expect(cleared.length).toBe(5)
  expect(cleared.every(call => JSON.stringify(call.args.query).includes('"values":["critical","high","medium"]'))).toBe(true)
  await ui.unmount()
})

test('Show more asks for the next page of rows', async ($, on) => {
  const asked = world(on, `git@github.com:${REPO}.git`)
  const ui = await opened($)
  asked.length = 0

  await ui.press({ key: 'show-more' })
  const lists = asked.filter(isList)
  expect(lists.length).toBe(10)
  expect(Math.max(...lists.map(call => call.args.offset as number))).toBe(45)
  await ui.unmount()
})

test('a tab shows what came back when an answer is not JSON', async ($, on) => {
  world(on, `git@github.com:${REPO}.git`, 'Error: upstream timed out after 30s')
  const ui = await opened($)
  expect(await ui.find({ type: 'Text', text: /upstream timed out after 30s/ })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: /JSON Parse error/ })).toBeUndefined()
  await ui.unmount()
})

test('a named repository wins over the session one', async ($, on) => {
  const asked = world(on, null)
  const ui = await opened($, ' acme-corp/billing-api ')
  expect(await ui.find({ type: 'Text', text: 'acme-corp/billing-api' })).toBeDefined()
  expect(JSON.stringify(asked.at(-1)?.args.query)).toContain('acme-corp/billing-api')
  await ui.unmount()
})

test('the panel says so outside a repository', async ($, on) => {
  world(on, null)
  const ui = await opened($)
  expect(await ui.find({ type: 'Text', text: /isn't in a git repository/ })).toBeDefined()
  await ui.unmount()
})
