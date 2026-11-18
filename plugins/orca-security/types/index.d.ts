export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational'

export type RiskFilter = 'all' | RiskLevel

/** The repository panel's sections: findings in the code, alerts on what it deploys, what it deploys. */
export type Section = 'code' | 'cloud' | 'assets'

export type AlertRow = {
  id: string
  title: string
  risk: RiskLevel
  score: number | null
  status: string
  /** SAST, SCA, IaC… for code; the asset's type for cloud. */
  kind: string | null
  /** The file path for code; the asset's name for cloud. */
  where: string | null
  /** aws, gcp, azure… for cloud; null for code. */
  cloud: string | null
  /** What the Fix prompt is built from; each null where Orca has none. */
  category: string | null
  ruleId: string | null
  ruleType: string | null
  description: string | null
  recommendation: string | null
  startLine: number | null
  endLine: number | null
  /** The container image a cloud alert's asset runs. */
  image: string | null
  /** The CVE Orca ranks first, as "CVE-2025-15467 (CVSS 9.8)". */
  cve: string | null
  /** The package to upgrade and to what, as "next 15.2.2 → 15.2.6 (/app/package-lock.json)". */
  fix: string | null
}

export type AssetRow = {
  id: string
  name: string
  risk: RiskLevel
  score: number | null
  kind: string | null
  internetFacing: boolean
  /** Why Orca counts it a crown jewel, or null when it is not one. */
  crownJewel: string | null
  region: string | null
  /** Orca's per-instance id (UiUniqueField), telling apart assets that share a name. */
  uid: string | null
}

export type SectionView<Row> = {
  /** The list's state; counts load with every refresh, a list only once its section is open. */
  status: 'idle' | 'loading' | 'ready' | 'error'
  rows: Row[]
  counts: Partial<Record<RiskLevel, number>>
  total: number
  /**
   * Its total over every risk, low and informational too: asked only when
   * `total` is 0 on Cloud or Assets, to say why the tab is empty; null when not
   * asked or not answered.
   */
  everyRisk: number | null
  error: string | null
}

export type RepoView = {
  status: 'idle' | 'loading' | 'ready' | 'no-repo' | 'no-orca' | 'error'
  repo: string | null
  code: SectionView<AlertRow>
  cloud: SectionView<AlertRow>
  assets: SectionView<AssetRow>
  updatedAt: number | null
  error: string | null
}

declare module 'claude-code' {
  interface PluginState {
    'orca-security': {
      repoView: Shaped<RepoView>
      riskFilter: RiskFilter
      /** A repository named with /orca owner/repo, in place of the session's own. */
      namedRepo: string | null
      /** The tab on show. */
      tab: Section
      /** How many rows each tab lists; "Show more" adds a page. */
      shown: Record<Section, number>
      /** Groups showing every location, not just the first few: 'code:<hash>'. */
      expanded: string[]
    }
  }
}
