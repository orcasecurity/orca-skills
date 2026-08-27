## Python (PyPI)

### requirements.txt

Edit the pin in place, keeping any extras and environment markers:

```
-pillow==8.3.1
+pillow==12.3.0

# extras and markers are part of the requirement — keep them
-requests[security]==2.20.0 ; python_version >= "3.8"
+requests[security]==2.31.0 ; python_version >= "3.8"
```

Use `==` even if the line previously used a range. An exact pin is what the
resolver assumed when it decided the target.

There is no lockfile to regenerate for a plain `requirements.txt`. Do **not**
run `pip install` to "apply" the change — it mutates the environment this agent
runs in, not the repository.

### pyproject.toml

Poetry:
```toml
[tool.poetry.dependencies]
pillow = "12.3.0"
```
Then `poetry lock --no-update` if `poetry.lock` exists and poetry is installed.

PEP 621:
```toml
[project]
dependencies = ["pillow==12.3.0"]
```

### uv / pip-tools

- `uv.lock` present: `uv lock --upgrade-package pillow`
- `requirements.in` present: edit the `.in`, then `pip-compile requirements.in`

If the tool is not installed, edit the manifest and put the regeneration command
in `manual_steps`.

### Watch for

A major-version bump often raises the minimum Python version and may remove
public APIs. Do not adapt calling code — that is out of scope for this fix — but
**do** note it in `manual_steps` so a reviewer checks it, e.g.:

- "Pillow 10 removed `Image.ANTIALIAS`; grep for it before deploying"
- "Pillow 12 requires Python >= 3.10; confirm the runtime image"

Also flag a conflict you can see in the same file, such as another package
pinned to a version incompatible with the new floor.
