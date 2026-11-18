// The panel's small pictures, as SVG documents: the platform's filled risk badge,
// the risk mix of a tab as one bar, and the hairline between list entries. Pure,
// so a test reads the markup. The desktop draws an Svg as an image; the terminal
// has no Svg, and the panel draws text there instead.

import type { RiskLevel } from '../../types'

// The Orca platform's risk colors, drawn the way the platform draws a filled risk
// badge: the risk color behind dark text, which reads the same on a light or a
// dark panel.
export const RISK_COLOR: Record<RiskLevel, string> = {
  critical: '#ff534c',
  high: '#ff9839',
  medium: '#fadd69',
  low: '#9dcdfb',
  informational: '#cacfdb',
}
export const BADGE_TEXT = '#10111d'

/** A badge's height in CSS pixels: one line of body text. */
export const PILL_HEIGHT = 20
/** A score badge's width, the same for every score so a column of them lines up ("10.0" the widest). */
export const SCORE_WIDTH = 38

const FONT = "Geist, Mulish, -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif"

function escaped(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

/** A count badge's width: 24 wide at least, 6 of padding either side. */
export function pillWidth(text: string): number {
  return Math.max(24, 12 + Math.ceil(text.length * 7.4))
}

/** A filled risk badge: radius 4, 12px semibold, figures of one width. */
export function riskPill(risk: RiskLevel, text: string, width = pillWidth(text)): string {
  const h = PILL_HEIGHT
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${h}" viewBox="0 0 ${width} ${h}">` +
    `<rect width="${width}" height="${h}" rx="4" fill="${RISK_COLOR[risk]}"/>` +
    `<text x="${width / 2}" y="${h / 2}" text-anchor="middle" dominant-baseline="central" ` +
    `font-family="${FONT}" font-size="12" font-weight="600" fill="${BADGE_TEXT}" ` +
    `style="font-variant-numeric: tabular-nums">${escaped(text)}</text></svg>`
  )
}

/**
 * The bar's drawing, in its own units: wider than any panel, so it is drawn as
 * wide as the panel, and scaled evenly, so its height, round ends and gaps keep
 * their proportions: 6 px tall, 3 px ends and 2 px gaps on a 400 px panel. (An
 * image stretched to a height of its own squashes the ends and gaps sideways.)
 */
export const BAR_WIDTH = 4000
const BAR_HEIGHT = 60
const BAR_GAP = 20
/** The least a risk with any takes: a few among many still seen. */
const BAR_MIN = 80

/** Each risk's stretch of the bar in its units, critical first, the risks with none left out; null when there is nothing. */
export function barSegments(
  counts: Partial<Record<RiskLevel, number>>,
  risks: readonly RiskLevel[],
): Array<{ risk: RiskLevel; x: number; width: number }> | null {
  const shown = risks.map(risk => ({ risk, count: counts[risk] ?? 0 })).filter(s => s.count > 0)
  const total = shown.reduce((sum, s) => sum + s.count, 0)
  if (total === 0) {
    return null
  }
  const room = BAR_WIDTH - BAR_GAP * (shown.length - 1)
  const widths = shown.map(s => Math.max(BAR_MIN, Math.round((s.count / total) * room)))
  // The largest gives way for the small ones lifted to BAR_MIN.
  const largest = widths.indexOf(Math.max(...widths))
  widths[largest] = (widths[largest] ?? 0) + room - widths.reduce((sum, w) => sum + w, 0)
  let x = 0
  return shown.map((s, i) => {
    const width = widths[i] ?? 0
    const segment = { risk: s.risk, x, width }
    x += width + BAR_GAP
    return segment
  })
}

/** The risk mix as one bar across the panel, each risk a rounded segment; null when there is nothing. */
export function severityBar(counts: Partial<Record<RiskLevel, number>>, risks: readonly RiskLevel[]): string | null {
  const segments = barSegments(counts, risks)
  if (segments === null) {
    return null
  }
  const rects = segments
    .map(
      s =>
        `<rect x="${s.x}" width="${s.width}" height="${BAR_HEIGHT}" rx="${BAR_HEIGHT / 2}" fill="${RISK_COLOR[s.risk]}"/>`,
    )
    .join('')
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${BAR_WIDTH}" height="${BAR_HEIGHT}" ` +
    `viewBox="0 0 ${BAR_WIDTH} ${BAR_HEIGHT}">${rects}</svg>`
  )
}

/**
 * A hairline as wide as the panel: wider than any panel, so the image takes the
 * slot's width, and stretched to one pixel tall. A grey at a third of full
 * strength, faint on a light or a dark panel alike.
 */
export const DIVIDER =
  '<svg xmlns="http://www.w3.org/2000/svg" width="4000" height="1" viewBox="0 0 4000 1" preserveAspectRatio="none">' +
  '<rect width="4000" height="1" fill="#80808055"/></svg>'

/** The faint fill under the entry the pointer is on. */
export const HOVER_FILL = '#8080801f'
