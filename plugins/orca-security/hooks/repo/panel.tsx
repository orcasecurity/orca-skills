// The repository panel: /orca [owner/repo] opens a side panel of what Orca sees
// for a repository, one tab at a time: Code (alerts on the repository), Cloud
// (alerts on the cloud assets deployed from it) and Assets (those assets).
// Every alert shows where it is and what to do about it (Fix, Review or
// Investigate, by its kind), with no click to reveal them.
// A button's prompt is sent as the person's own words (`asUser`): they pressed it,
// so the model reads it bare, without the "plugin sent a message" frame.
// Counts load on every refresh; a tab's list loads when the tab is first shown.
//
// Text wraps and is never truncated: the desktop surface clips a truncated Text
// at the panel's edge instead of ending it with an ellipsis.

import { atom, read, update } from 'claude-code'
import type { EngineInterface, On, Timer } from 'claude-code'

import type { AlertRow, AssetRow, RepoView, RiskFilter, RiskLevel, Section, SectionView } from '../../types'
import { actionOf, alertPrompt, approachOf } from './prompts'
import {
  alertRowsOf,
  alertUrl,
  assetGroupsOf,
  assetRowsOf,
  assetUrl,
  countsCall,
  countsOf,
  countText,
  everyRiskCall,
  everyRiskTotalOf,
  groupsOf,
  listCalls,
  locationOf,
  pagesOf,
  repoNameOf,
  scoreText,
  SECTIONS,
  SHOWN_RISKS,
  shownFilter,
  svlOf,
  uniqueById,
} from './queries'
import type { AlertGroup, AssetGroup, SvlArgs } from './queries'
import { BADGE_TEXT, DIVIDER, HOVER_FILL, PILL_HEIGHT, pillWidth, RISK_COLOR, riskPill, SCORE_WIDTH, severityBar } from './marks'

const PANE = 'orca-repo'
const COMMAND = 'orca'
const REFRESH_MS = 5 * 60 * 1000
/** Rows a tab lists at first, and adds with each "Show more". */
const PAGE = 25
const MAX_SHOWN = 100
/** Locations a group lists before "+N more". */
const PLACES = 3

function emptySection<Row>(): SectionView<Row> {
  return { status: 'idle', rows: [], counts: {}, total: 0, everyRisk: null, error: null }
}

const EMPTY: RepoView = {
  status: 'idle',
  repo: null,
  code: emptySection<AlertRow>(),
  cloud: emptySection<AlertRow>(),
  assets: emptySection<AssetRow>(),
  updatedAt: null,
  error: null,
}

// Change the tag when RepoView's fields change: an earlier shape is declined.
const view = atom({ plugin: 'orca-security', key: 'repoView' } as const, EMPTY, { shape: 'repo-view-4' })
const riskFilter = atom({ plugin: 'orca-security', key: 'riskFilter' } as const, 'all' as RiskFilter)
const namedRepo = atom({ plugin: 'orca-security', key: 'namedRepo' } as const, null as string | null)
const tab = atom({ plugin: 'orca-security', key: 'tab' } as const, 'code' as Section)
const shown = atom({ plugin: 'orca-security', key: 'shown' } as const, {
  code: PAGE,
  cloud: PAGE,
  assets: PAGE,
} as Record<Section, number>)
const expanded = atom({ plugin: 'orca-security', key: 'expanded' } as const, [] as string[])

const DANGER = '#ff3342'
const CROWN = '#ff9839'

const RISK_LABEL: Record<RiskLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Info',
}

const TAB_TITLE: Record<Section, string> = { code: 'Code', cloud: 'Cloud', assets: 'Assets' }
const TAB_HINT: Record<Section, string> = {
  code: 'Open alerts on the repository: SAST, SCA, IaC and secrets.',
  cloud: 'Open alerts on cloud assets deployed from this repository.',
  assets: 'Cloud assets deployed from this repository.',
}

function put($: EngineInterface, change: (old: RepoView) => RepoView): Promise<RepoView> {
  return update($, view, change)
}

/** The tab's list state set, its rows kept. */
function marked(old: RepoView, section: Section, status: SectionView<unknown>['status'], error: string | null = null): RepoView {
  switch (section) {
    case 'code':
      return { ...old, code: { ...old.code, status, error } }
    case 'cloud':
      return { ...old, cloud: { ...old.cloud, status, error } }
    case 'assets':
      return { ...old, assets: { ...old.assets, status, error } }
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** The Orca MCP server's name in this session: whichever exposes run_svl_query. */
async function orcaServer($: EngineInterface): Promise<string | null> {
  const tools = await $.tool.list()
  for (const tool of tools) {
    const match = /^mcp__(.+)__run_svl_query$/.exec(tool.name)
    if (tool.mcp && match?.[1] !== undefined) {
      return match[1]
    }
  }
  return null
}

type Target = { repo: string; call: (args: SvlArgs) => ReturnType<EngineInterface['mcp']['call']> }

/** The repository to show and the way to ask Orca about it; null, with the view saying why. */
async function target($: EngineInterface): Promise<Target | null> {
  const repo = (await read($, namedRepo)) ?? repoNameOf((await $.session.repo())?.remote)
  if (repo === null) {
    await put($, () => ({ ...EMPTY, status: 'no-repo' }))
    return null
  }
  const server = await orcaServer($)
  if (server === null) {
    await put($, () => ({ ...EMPTY, status: 'no-orca', repo }))
    return null
  }
  // Another repository's rows never show under this one's name.
  await put($, old => (old.repo === repo ? old : { ...EMPTY, repo }))
  return { repo, call: args => $.mcp.call(server, 'run_svl_query', args) }
}

async function loadCounts($: EngineInterface, t: Target): Promise<void> {
  const answers = await Promise.all(SECTIONS.map(section => t.call(countsCall(section, t.repo))))
  const [code, cloud, assets] = answers.map(answer => countsOf(svlOf(answer)))
  if (code === undefined || cloud === undefined || assets === undefined) {
    throw new Error('Orca returned no counts')
  }
  // An empty Cloud or Assets tab: is anything traced to the repository at all,
  // or only risks the panel leaves out? Unanswered, the tab says less.
  const everyRisk = (section: Section) =>
    t.call(everyRiskCall(section, t.repo)).then(answer => everyRiskTotalOf(svlOf(answer)), () => null)
  const linked = assets.total === 0 ? await everyRisk('assets') : null
  const cloudEvery = cloud.total === 0 && linked !== 0 ? await everyRisk('cloud') : null
  await put($, old => ({
    ...old,
    code: { ...old.code, ...code, everyRisk: null },
    cloud: { ...old.cloud, ...cloud, everyRisk: cloudEvery },
    assets: { ...old.assets, ...assets, everyRisk: linked },
  }))
}

/** A tab's list, for the risk filter and length as they stand; its errors stay in the tab. */
async function loadList($: EngineInterface, t: Target, section: Section): Promise<void> {
  const filter = await read($, riskFilter)
  const count = (await read($, shown))[section]
  await put($, old => marked(old, section, 'loading'))
  const calls = listCalls(section, t.repo, filter, count)
  // Where an answer is too large for the MCP client, the file it was saved to.
  const readSaved = (path: string) => $.fs.read(path)
  try {
    if (section === 'assets') {
      const pages = await Promise.all(calls.map(page => pagesOf(t.call, page, assetRowsOf, readSaved)))
      const rows = uniqueById(pages.flat())
      await put($, old => ({ ...old, assets: { ...old.assets, status: 'ready', rows, error: null } }))
    } else {
      const pages = await Promise.all(calls.map(page => pagesOf(t.call, page, svl => alertRowsOf(svl, section), readSaved)))
      const rows = uniqueById(pages.flat())
      await put($, old =>
        section === 'code'
          ? { ...old, code: { ...old.code, status: 'ready', rows, error: null } }
          : { ...old, cloud: { ...old.cloud, status: 'ready', rows, error: null } },
      )
    }
  } catch (error) {
    await put($, old => marked(old, section, 'error', messageOf(error)))
  }
}

async function refresh($: EngineInterface): Promise<void> {
  const t = await target($)
  if (t === null) {
    return
  }
  await put($, old => ({ ...old, status: 'loading', error: null }))
  const list = loadList($, t, await read($, tab))
  try {
    await Promise.all([loadCounts($, t), list])
    const updatedAt = await $.clock.now()
    await put($, old => ({ ...old, status: 'ready', updatedAt }))
  } catch (error) {
    await list
    await put($, old => ({ ...old, status: 'error', error: messageOf(error) }))
  }
}

async function showTab($: EngineInterface, section: Section): Promise<void> {
  await update($, tab, () => section)
  const status = (await read($, view))[section].status
  if (status === 'ready' || status === 'loading') {
    return
  }
  const t = await target($)
  if (t !== null) {
    await loadList($, t, section)
  }
}

/** Pressing the chosen risk again clears it. Other tabs load afresh when shown. */
async function chooseRisk($: EngineInterface, risk: RiskFilter): Promise<void> {
  const next = await update($, riskFilter, old => (shownFilter(old) === risk ? 'all' : risk))
  await put($, old => SECTIONS.reduce((acc, section) => marked(acc, section, 'idle'), old))
  const t = await target($)
  if (t === null || (await read($, riskFilter)) !== next) {
    return
  }
  await loadList($, t, await read($, tab))
}

async function showMore($: EngineInterface): Promise<void> {
  const section = await read($, tab)
  await update($, shown, old => ({ ...old, [section]: Math.min(MAX_SHOWN, old[section] + PAGE) }))
  const t = await target($)
  if (t !== null) {
    await loadList($, t, section)
  }
}

async function toggle($: EngineInterface, key: string): Promise<void> {
  await update($, expanded, keys => (keys.includes(key) ? keys.filter(k => k !== key) : [...keys, key]))
}

function ago(then: number | null, now: number): string {
  if (then === null) {
    return 'not loaded yet'
  }
  const minutes = Math.round((now - then) / 60000)
  return minutes < 1 ? 'updated just now' : minutes === 1 ? 'updated 1 min ago' : `updated ${minutes} min ago`
}

function plural(n: number, one: string, many: string): string {
  return `${countText(n)} ${n === 1 ? one : many}`
}

export function repoPanel(on: On): void {
  let ticker: Timer | undefined

  const stopTicker = () => {
    ticker?.cancel()
    ticker = undefined
  }

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: COMMAND,
      description: "Show Orca's alerts and assets for this session's repository (or the one named) in a side panel",
      argumentHint: '[owner/repo]',
      immediate: true,
    })
    return next(e)
  })

  on('command.run', { command: COMMAND }, async ($, e) => {
    const arg = e.args.trim()
    await update($, namedRepo, () => (arg === '' ? null : arg))
    await $.ui.open({ id: PANE, title: 'Orca Security' })
    stopTicker()
    ticker = $.clock.every(REFRESH_MS, () => void refresh($))
    void refresh($)
    return {}
  }).catch(() => ({ text: "Couldn't open the Orca Security panel." }))

  on('ui.close', async ($, e, next) => {
    if (e.id === PANE) {
      stopTicker()
    }
    return next(e)
  }).catch(($, e, next) => next(e))

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const elements = $.ui.resolve(e)
    const { Box, Button, Link, Text } = elements
    // The pictures (badges, the risk bar, dividers) where the surface draws Svg;
    // the terminal draws text badges and plain gaps instead. Asked by surface: the
    // terminal's table answers an Svg that draws an empty Box.
    const Svg = e.surface !== 'terminal' && 'Svg' in elements ? elements.Svg : null
    const state = await read($, view)
    const filter = shownFilter(await read($, riskFilter))
    const current = await read($, tab)
    const open = await read($, expanded)
    const now = await $.clock.now()
    const repo = state.repo ?? 'this repository'

    const refreshButton = (
      <Button
        key="refresh"
        label={state.status === 'loading' ? 'Refreshing…' : 'Refresh'}
        hotkey="r"
        onPress={() => refresh($)}
      />
    )

    const notice = (text: string) => (
      <Box flexDirection="column" gap={1}>
        <Text dimColor>{text}</Text>
        {refreshButton}
      </Box>
    )
    if (state.status === 'no-repo') {
      return notice("This session isn't in a git repository with an origin remote. Run /orca owner/repo to look one up by name.")
    }
    if (state.status === 'no-orca') {
      return notice('No Orca Security MCP server is connected in this session. Connect it, then refresh.')
    }
    if (state.status === 'idle' || (state.status === 'loading' && state.updatedAt === null)) {
      return notice(`Asking Orca about ${repo}…`)
    }

    /** A filled risk badge, as the platform draws one; `width` fixes it, for a column of scores. */
    const badge = (risk: RiskLevel, text: string, alt: string, width = pillWidth(text)) =>
      Svg === null ? (
        <Text backgroundColor={RISK_COLOR[risk]} color={BADGE_TEXT} weight="semibold" tabular>
          {` ${text} `}
        </Text>
      ) : (
        <Svg source={riskPill(risk, text, width)} alt={alt} width={width} height={PILL_HEIGHT} />
      )
    const scoreBadge = (risk: RiskLevel, score: number | null) =>
      badge(risk, scoreText(score), `${RISK_LABEL[risk]} risk, Orca score ${scoreText(score)}`, SCORE_WIDTH)

    /** A list entry: lit under the pointer and set in a little where pictures are drawn. */
    const entry = Svg === null ? {} : { hover: { backgroundColor: HOVER_FILL }, paddingX: 'sm' as const, paddingY: 'xs' as const }

    const data: SectionView<AlertRow | AssetRow> = state[current]

    const header = (
      <Box flexDirection="row" justifyContent="space-between" alignItems="flex-start" columnGap={1}>
        <Box flexDirection="column" flexShrink={1}>
          <Text weight="semibold">{state.repo}</Text>
          <Text size="caption" dimColor>
            {plural(state.code.total + state.cloud.total, 'open alert', 'open alerts')} ·{' '}
            {plural(state.assets.total, 'asset', 'assets')} · {ago(state.updatedAt, now)}
          </Text>
        </Box>
        {refreshButton}
      </Box>
    )

    const tabs = (
      <Box flexDirection="row" flexWrap="wrap" columnGap={1} rowGap={1}>
        {SECTIONS.map(section => (
          <Button
            key={`tab-${section}`}
            {...(section === current ? { variant: 'primary' as const } : {})}
            label={`${TAB_TITLE[section]} ${countText(state[section].total)}`}
            onPress={() => showTab($, section)}
          />
        ))}
      </Box>
    )

    const bar = Svg === null ? null : severityBar(data.counts, SHOWN_RISKS)
    const barAlt = SHOWN_RISKS.filter(level => (data.counts[level] ?? 0) > 0)
      .map(level => `${countText(data.counts[level] ?? 0)} ${RISK_LABEL[level].toLowerCase()}`)
      .join(', ')

    const riskRow = (
      <Box flexDirection="column" rowGap="sm">
        {Svg !== null && bar !== null && <Svg source={bar} alt={`Risk mix: ${barAlt}`} />}
        <Box flexDirection="row" flexWrap="wrap" columnGap={2} rowGap={1} alignItems="center">
          {SHOWN_RISKS.filter(level => (data.counts[level] ?? 0) > 0).map(level => (
          <Box key={`chip-${level}`} flexDirection="row" columnGap={1} alignItems="center">
            {badge(level, countText(data.counts[level] ?? 0), `${countText(data.counts[level] ?? 0)} ${RISK_LABEL[level]}`)}
            <Button
              key={`filter-${level}`}
              plain
              dimColor={filter !== 'all' && filter !== level}
              label={filter === level ? `${RISK_LABEL[level]} ✓` : RISK_LABEL[level]}
              onPress={() => chooseRisk($, level)}
            />
          </Box>
          ))}
        </Box>
      </Box>
    )

    /** Why an empty Cloud or Assets tab is empty, where the every-risk count says. */
    const emptyReason = (section: Section): string | null => {
      const notTraced = "Orca hasn't traced any cloud assets to this repository (no Code Origin links)."
      const linked = state.assets.total === 0 ? state.assets.everyRisk : null
      if (section === 'code' || linked === 0) {
        return section === 'code' ? null : notTraced
      }
      if (section === 'assets') {
        return linked === null
          ? null
          : `${plural(linked, 'cloud asset is', 'cloud assets are')} deployed from this repository, none critical, high or medium.`
      }
      const every = state.cloud.everyRisk
      if (every === null) {
        return null
      }
      return every === 0
        ? 'No open alerts on the cloud assets deployed from this repository.'
        : `${plural(every, 'open alert', 'open alerts')} on cloud assets deployed from this repository, none critical, high or medium.`
    }

    const listState = () => {
      if (data.status === 'error') {
        return <Text color={DANGER}>Couldn't load the list: {data.error}</Text>
      }
      if (data.rows.length === 0 && data.status !== 'ready') {
        return <Text dimColor>Loading…</Text>
      }
      if (data.rows.length === 0) {
        const why = filter === 'all' ? emptyReason(current) : null
        if (why !== null) {
          return <Text dimColor>{why}</Text>
        }
        const what = current === 'assets' ? 'assets' : 'open alerts'
        return <Text dimColor>{filter === 'all' ? `No ${what}.` : `No ${RISK_LABEL[filter].toLowerCase()} ${what}.`}</Text>
      }
      return null
    }

    /** "+N more" or "Show fewer" under a group that has more places than it lists. */
    const moreButton = (key: string, all: number) => {
      if (all <= PLACES) {
        return null
      }
      const isOpen = open.includes(key)
      return (
        <Button
          key={`more-${key}`}
          plain
          dimColor
          label={isOpen ? 'Show fewer' : `+${all - PLACES} more`}
          onPress={() => toggle($, key)}
        />
      )
    }

    const alertPlace = (section: 'code' | 'cloud', alert: AlertRow) => {
      const { main, detail } = locationOf(alert, section)
      return (
        <Box key={`alert-${alert.id}`} flexDirection="row" justifyContent="space-between" alignItems="flex-start" columnGap={2}>
          <Box flexShrink={1}>
            <Text size="caption">
              {section === 'code' ? <Text mono>{main}</Text> : main}
              {detail === '' ? '' : <Text dimColor>{`  ${detail}`}</Text>}
            </Text>
          </Box>
          <Box flexDirection="row" columnGap={2} flexShrink={0}>
            <Button
              key={`act-${alert.id}`}
              plain
              label={actionOf(approachOf(alert, section))}
              onPress={() => $.prompt.submit({ text: alertPrompt(alert, section, repo), asUser: true })}
            />
            <Link href={alertUrl(alert.id)} label="Open" />
          </Box>
        </Box>
      )
    }

    const alertGroup = (section: 'code' | 'cloud', group: AlertGroup) => {
      const key = `${section}:${group.key}`
      const all = open.includes(key) ? group.alerts : group.alerts.slice(0, PLACES)
      return (
        <Box key={`group-${key}`} flexDirection="row" columnGap={1} alignItems="flex-start" {...entry}>
          <Box flexShrink={0}>{scoreBadge(group.risk, group.score)}</Box>
          <Box flexDirection="column" flexShrink={1} flexGrow={1}>
            <Text weight="medium">{group.title}</Text>
            {all.map(alert => alertPlace(section, alert))}
            {moreButton(key, group.alerts.length)}
          </Box>
        </Box>
      )
    }

    const assetActions = (asset: AssetRow) => (
      <Box flexDirection="row" columnGap={2} flexShrink={0}>
        <Button
          key={`profile-${asset.id}`}
          plain
          label="Profile"
          onPress={() =>
            $.prompt.submit({ text: `Show the Orca asset profile for ${asset.name} (${assetUrl(asset.id)}).`, asUser: true })
          }
        />
        <Link href={assetUrl(asset.id)} label="Open" />
      </Box>
    )

    const assetGroup = (group: AssetGroup) => {
      const first = group.assets[0]
      if (first === undefined) {
        return null
      }
      const key = `assets:${group.key}`
      const facts = [first.kind, first.internetFacing ? 'internet-facing' : null, first.region]
        .filter(Boolean)
        .join(' · ')
      const many = group.assets.length > 1
      const listed = open.includes(key) ? group.assets : group.assets.slice(0, PLACES)
      return (
        <Box key={`group-${key}`} flexDirection="row" columnGap={1} alignItems="flex-start" {...entry}>
          <Box flexShrink={0}>{scoreBadge(first.risk, first.score)}</Box>
          <Box flexDirection="column" flexShrink={1} flexGrow={1}>
            <Text weight="medium">
              {group.name}
              {many ? <Text dimColor>{`  ×${group.assets.length}`}</Text> : ''}
            </Text>
            <Box flexDirection="row" justifyContent="space-between" alignItems="flex-start" columnGap={2}>
              <Box flexShrink={1} flexDirection="column">
                <Text size="caption" dimColor>
                  {facts}
                </Text>
                {first.crownJewel !== null && (
                  <Text size="caption" color={CROWN}>
                    ♛ Crown jewel · {first.crownJewel}
                  </Text>
                )}
              </Box>
              {many ? null : assetActions(first)}
            </Box>
            {many &&
              listed.map(asset => (
                <Box key={`instance-${asset.id}`} flexDirection="row" justifyContent="space-between" alignItems="flex-start" columnGap={2}>
                  <Box flexShrink={1}>
                    <Text size="caption" mono>
                      {asset.uid ?? asset.id}
                    </Text>
                  </Box>
                  {assetActions(asset)}
                </Box>
              ))}
            {many && moreButton(key, group.assets.length)}
          </Box>
        </Box>
      )
    }

    const matching = filter === 'all' ? data.total : (data.counts[filter] ?? 0)
    const footer =
      data.rows.length === 0 ? null : (
        <Box flexDirection="row" justifyContent="space-between" alignItems="center" columnGap={1}>
          <Text size="caption" dimColor>
            Showing the top {data.rows.length} of {countText(matching)}
            {filter === 'all' ? '' : ` ${RISK_LABEL[filter].toLowerCase()}`} by Orca score
          </Text>
          {matching > data.rows.length && data.rows.length < MAX_SHOWN && data.status === 'ready' && (
            <Button key="show-more" plain label={`Show ${PAGE} more`} onPress={() => showMore($)} />
          )}
        </Box>
      )

    const entries =
      current === 'assets'
        ? assetGroupsOf(state.assets.rows).map(assetGroup)
        : groupsOf(state[current].rows).map(group => alertGroup(current, group))
    // A hairline between entries where pictures are drawn; a blank row on the terminal.
    const list = entries
      .filter(group => group !== null)
      .flatMap((group, i) => (i === 0 || Svg === null ? [group] : [<Svg source={DIVIDER} alt="separator" height={1} />, group]))

    return (
      <Box flexDirection="column" gap={1}>
        {header}
        {state.status === 'error' && <Text color={DANGER}>Couldn't reach Orca: {state.error}</Text>}
        {tabs}
        <Text size="caption" dimColor>
          {TAB_HINT[current]}
        </Text>
        {riskRow}
        {listState()}
        <Box flexDirection="column" rowGap={Svg === null ? 1 : 'xs'}>
          {list}
        </Box>
        {footer}
      </Box>
    )
  })
}
