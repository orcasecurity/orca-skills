# orca-security

Orca Security in Claude Code, read through the Orca MCP server.

`/orca [owner/repo]` opens the **Orca Security** side panel for the session's
repository (or the one named), in three tabs:

- **Code**: open alerts on the repository itself (SAST, SCA, IaC, secrets)
- **Cloud**: open alerts on cloud assets whose Code Origin is the repository
- **Assets**: the cloud assets deployed from the repository

Each alert shows where it is, with a button that asks Claude to fix, review or
investigate it (by the kind of alert) and a link to it in Orca. Critical, high
and medium risks are shown; low and informational are left out. When the Cloud
or Assets tab is empty, it says whether Orca has traced no assets to the
repository or found nothing at those risks.

The panel draws in the Claude desktop app and in a terminal session.

## Install

You need the [Orca MCP server](../../README.md#mcp-configuration) connected in
Claude Code; the panel shows what your own Orca account can see.

```bash
/plugin marketplace add orcasecurity/orca-skills
/plugin install orca-security@orcasecurity
```

In the Claude desktop app, where `/plugin` does not run: click + next to the
prompt box, then Plugins, Add marketplace with `orcasecurity/orca-skills`, then
add `orca-security`.

## Develop

The plugin is a Claude Code mod: a hooks module (`hooks/register.tsx`) that adds
the `/orca` command and draws the pane. Each feature lives in its own folder
under `hooks/` (the panel is `hooks/repo/`) and registers in
`hooks/register.tsx`.

To run it from a checkout:

```bash
claude --plugin-dir plugins/orca-security
```

Then run `/reload-plugins` in that session after an edit.

```bash
claude plugin validate plugins/orca-security
claude plugin test plugins/orca-security
```

The tests use made-up repositories, assets and alert IDs.
