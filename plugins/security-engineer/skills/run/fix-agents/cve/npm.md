## Node.js (npm)

### package.json

```json
// Before
"dependencies": { "lodash": "^4.17.4" }

// After — pin exactly, do not keep the caret
"dependencies": { "lodash": "4.17.21" }
```

An exact pin is what the resolver assumed. Keeping `^` would let the install
resolve to something else on the next `npm install`.

### Regenerate the lockfile

```bash
npm install --package-lock-only --ignore-scripts
```

`--package-lock-only` updates `package-lock.json` without downloading packages or
touching `node_modules`, and `--ignore-scripts` avoids running lifecycle scripts
from the dependency tree. Both files must end up in the diff.

If the project uses yarn or pnpm, use that tool instead:
- `yarn install --mode update-lockfile`
- `pnpm install --lockfile-only`

### If the vulnerable package is transitive

A transitive package will not be in `package.json`. Add an override so the
resolution is pinned, then regenerate the lockfile:

```json
"overrides": { "lodash": "4.17.21" }
```

For yarn use `resolutions` instead of `overrides`. Say what you did in
`diff_summary` — an override is a different change from a direct bump and a
reviewer needs to see which one happened.

### Watch for

- A peer-dependency range that the new version violates. Note it in
  `manual_steps`; do not start bumping peers.
- A major bump changing the module format (CommonJS to ESM only). Flag it.
