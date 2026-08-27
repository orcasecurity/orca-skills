## Rust (Cargo)

### Cargo.toml

Both the string and table forms appear; edit whichever the file uses, keeping
features intact:

```toml
# string form
-serde = "1.0.100"
+serde = "1.0.200"

# table form — keep features
-tokio = { version = "1.20.0", features = ["full"] }
+tokio = { version = "1.24.2", features = ["full"] }
```

### Regenerate the lockfile

```bash
cargo update --package serde --precise 1.0.200
```

This touches only the named package. Plain `cargo update` bumps everything and
produces a diff nobody can review.

If the crate is transitive and not in `Cargo.toml`, `cargo update --package
<name> --precise <version>` still works — Cargo will update `Cargo.lock` alone.
Note in `diff_summary` that only the lockfile changed.

### If cargo is unavailable

Edit `Cargo.toml` and note in `manual_steps` that `Cargo.lock` needs
regenerating. For a lockfile-only fix with no cargo available, report failure —
hand-editing `Cargo.lock` checksums is not something to attempt.

### Watch for

- A bump that raises the minimum supported Rust version. Flag it; CI will fail on
  an older toolchain.
- A major bump on a crate that appears in your public API, which becomes a
  breaking change for downstream users of this crate.
