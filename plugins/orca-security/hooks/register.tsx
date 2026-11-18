// Orca Security in Claude Code. Each feature lives in its own folder under
// hooks/ and adds its hooks here; a new one is a folder and one line below.

import type { Register } from 'claude-code'

import { repoPanel } from './repo/panel'

export const register: Register = on => {
  repoPanel(on)
}
