## Go modules

### The canonical command

Prefer `go get` over hand-editing `go.mod` — it updates `go.mod` and `go.sum`
together, and a `go.sum` missing an entry breaks the build:

```bash
cd <directory containing go.mod>
go get golang.org/x/net@v0.17.0
go mod tidy
```

Keep the `v` prefix. Go module versions are `v1.2.3`, never `1.2.3`.

### If go is unavailable

Edit `go.mod` directly:

```
-	golang.org/x/net v0.0.0-20210119194325-5f4716e94777
+	golang.org/x/net v0.17.0
```

`go.sum` will then be missing hashes for the new version and the build will fail.
Say so in `manual_steps`: "Run `go mod tidy` to regenerate go.sum before merging."

### Indirect dependencies

A module marked `// indirect` is still bumped in `go.mod` the same way. `go get`
handles the marker; leave the comment as the tool leaves it.

If the vulnerable module is not in `go.mod` at all, it is pulled in deeply. Add
it explicitly with `go get`, which promotes it to a direct requirement — that is
the accepted way to force a transitive version in Go. Note it in `diff_summary`.

### Monorepos

Run in the directory holding the `go.mod` that declares the module, not the
repository root. The alert's file path tells you which one.

### Watch for

- `go mod tidy` removing requirements unrelated to your change. If the diff grows
  beyond the bump, say so in `diff_summary` rather than leaving it unexplained.
- A `go` directive raised by the new version, requiring a newer toolchain in CI.
