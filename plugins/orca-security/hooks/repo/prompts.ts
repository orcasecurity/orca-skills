// The prompts the repository panel's alert buttons send. Pure: built from a row
// alone. An alert is not always a vulnerability, so each is first sorted by what
// fixing it means, and the button and prompt follow from that.

import type { AlertRow } from '../../types'
import { alertUrl } from './queries'

/**
 * What acting on an alert means:
 *   code         SAST: change the code at the path
 *   iac          IaC: change the configuration in the file
 *   dependency   a vulnerable package: upgrade it where the repository pins it
 *   secret       a secret in the code: take it out (and say it needs rotating)
 *   license      OSS license: a decision, not a defect
 *   scm          SCM posture: a repository setting, not code
 *   cloud-config a misconfigured cloud asset: change the IaC that defines it
 *   runtime      a detection on a running asset (suspicious activity, malware,
 *                data at risk): investigate, don't patch
 */
export type Approach = 'code' | 'iac' | 'dependency' | 'secret' | 'license' | 'scm' | 'cloud-config' | 'runtime'

export type Action = 'Fix' | 'Review' | 'Investigate'

const RUNTIME = /suspicious|malware|malicious|system integrity|data at risk|anomal|attack|compromise/i

/** Sorts an alert by what acting on it means: a code alert by its scan type, a cloud one by its category. */
export function approachOf(alert: AlertRow, section: 'code' | 'cloud'): Approach {
  const packageFix = alert.fix !== null || alert.ruleType === 'vulnerability' || /^Vulnerabilities detected on /.test(alert.title)
  if (section === 'code') {
    switch (alert.kind) {
      case 'SAST':
        return 'code'
      case 'IaC':
        return 'iac'
      case 'Vulnerabilities':
      case 'SCA':
        return 'dependency'
      case 'Secret Detection':
        return 'secret'
      case 'OSS License':
        return 'license'
      case 'SCM Posture':
        return 'scm'
      default:
        return packageFix ? 'dependency' : /secret/i.test(alert.kind ?? '') ? 'secret' : 'code'
    }
  }
  if (alert.category === 'Vulnerabilities' || packageFix) {
    return 'dependency'
  }
  if (RUNTIME.test(alert.category ?? '') || RUNTIME.test(alert.title)) {
    return 'runtime'
  }
  return 'cloud-config'
}

export function actionOf(approach: Approach): Action {
  return approach === 'runtime' ? 'Investigate' : approach === 'license' || approach === 'scm' ? 'Review' : 'Fix'
}

function linesText(alert: AlertRow): string {
  if (alert.startLine === null) {
    return ''
  }
  const end = alert.endLine ?? alert.startLine
  return end === alert.startLine ? `#L${alert.startLine}` : `#L${alert.startLine}-L${end}`
}

/** What to do, in a sentence or two, for each approach. */
function taskOf(approach: Approach, repo: string): string {
  switch (approach) {
    case 'code':
      return 'Review the affected code and make a minimal, targeted fix that follows the remediation guidance and the codebase’s conventions.'
    case 'iac':
      return 'Change the configuration in that file so the check passes, following the remediation guidance. Keep the change to this resource.'
    case 'dependency':
      return 'Find where the repository declares or installs the affected package (manifest, lockfile, Dockerfile or base image) and upgrade it to the nearest version that fixes it. If the repository doesn’t install it (an OS package on a VM, say), say so and give the upgrade to run instead.'
    case 'secret':
      return 'Remove the secret from the code and read it from the configuration or secret store the codebase already uses. Removing it doesn’t make it safe: say in the summary that it has to be rotated, which can’t be done from here.'
    case 'license':
      return 'This is a license finding, not a defect. Find where the repository uses the package, explain the license concern, and lay out the options (replace it, remove it, or accept it). Don’t change anything until I choose.'
    case 'scm':
      return 'This is a repository setting, not code. Explain what to change in the repository’s settings and how, with the gh command where there is one. Don’t change any settings yourself.'
    case 'cloud-config':
      return `The asset is deployed from ${repo}: find where the repository defines it (Terraform, CloudFormation, Helm or Kubernetes manifests, Dockerfile) and change its configuration so the check passes. If the repository doesn’t set this, say so and give the console or CLI change instead of editing code.`
    case 'runtime':
      return `This is a detection on a running cloud asset, not a code finding. Use the Orca tools to look at the alert, its timeline and the asset, and tell me whether it looks like a real threat and what to do next. Check whether anything in ${repo} (deployed code, IaC, container image) contributes to it, and don’t change code unless the cause is clearly there.`
  }
}

/**
 * Asks Claude to act on one alert: the alert's facts, its description, what to
 * do for its kind, and the rules for a minimal change where it is one.
 */
export function alertPrompt(alert: AlertRow, section: 'code' | 'cloud', repo: string): string {
  const approach = approachOf(alert, section)
  const action = actionOf(approach)
  const asset =
    section === 'cloud'
      ? [alert.where, alert.kind, alert.cloud?.toUpperCase(), alert.image === null ? null : `image ${alert.image}`]
          .filter(Boolean)
          .join(' · ')
      : repo
  const type = section === 'code' ? [alert.kind, alert.category] : [alert.category]

  const facts: Array<[string, string | null]> = [
    ['Alert Name', alert.title],
    ['Alert ID', `${alert.id} (${alertUrl(alert.id)})`],
    ['Path', section === 'code' && alert.where !== null ? `${alert.where}${linesText(alert)}` : null],
    ['Asset', asset || null],
    ['Type', type.filter(Boolean).join(' · ') || null],
    ['Rule ID', alert.ruleId],
    ['Package', alert.fix],
    ['Top CVE', alert.cve],
    ['Remediation Guidance', alert.recommendation],
  ]

  const lines = [
    action === 'Fix'
      ? 'Fix the following security alert:'
      : action === 'Review'
        ? 'Review the following Orca alert:'
        : 'Investigate the following Orca alert:',
  ]
  for (const [label, value] of facts) {
    if (value !== null) {
      lines.push(`${label}: ${value}`)
    }
  }
  if (alert.description !== null) {
    lines.push('', 'Description:', alert.description)
  }
  lines.push('', taskOf(approach, repo))

  if (action === 'Fix') {
    lines.push(
      '',
      '- Only change what this alert is about; no unrelated refactoring.',
      approach === 'dependency'
        ? '- Upgrade only the affected package; leave other dependencies as they are.'
        : '- Do not change dependencies or package versions.',
      '- Run the existing tests, linters or IaC validation, and add a test covering the fix where the codebase has tests.',
      '- Finish with a short summary of what changed and how it resolves the alert.',
    )
  }
  return lines.join('\n')
}
