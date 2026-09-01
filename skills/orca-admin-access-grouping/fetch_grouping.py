#!/usr/bin/env python3
"""Fetch Orca's admin clustering artifact (GET /api/iaminator).

Reads an Orca API token from the first place it is found, derives the regional
API host, makes one read-only GET, and writes the JSON response to --out.

The token is never printed and never written to the output file. Only the
credential's *source*, the host, and the HTTP result go to stdout.

Exit codes:
  0  success, artifact written to --out
  2  no usable credential found (setup needed)
  3  the API answered with an error status
  4  could not reach the host
"""

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

# Values a scaffolded config leaves behind. Treated as "not configured" so they
# never become a confusing 401.
PLACEHOLDER = re.compile(
    r"^\s*$|YOUR_|PASTE|_HERE\b|^<.*>$|CHANGE_?ME|xxx+|\.\.\.", re.IGNORECASE
)


def usable(value):
    if not value:
        return ""
    value = value.strip()
    return "" if PLACEHOLDER.search(value) else value


def token_from_file(path):
    """First non-empty, non-comment line. Accepts bare tokens and KEY=value."""
    try:
        with open(path) as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line and not line.startswith("ey"):
                    line = line.split("=", 1)[1]
                return usable(line.strip().strip("'\""))
    except OSError:
        pass
    return ""


def from_mcp_json(path):
    """Return (token, base, status) from an .mcp.json.

    `status` describes the file for the diagnostic list. An OAuth-configured
    MCP has a perfectly valid orca-security entry that simply carries no
    credential; saying "absent or no entry" there tells the user their MCP
    setup is broken when it is fine.
    """
    try:
        with open(path) as handle:
            config = json.load(handle)
    except OSError:
        return "", "", "absent"
    except json.JSONDecodeError as exc:
        return "", "", f"present but not valid JSON ({exc})"

    servers = (config or {}).get("mcpServers")
    if not isinstance(servers, dict):
        return "", "", "present but has no mcpServers"
    server = servers.get("orca-security")
    if not isinstance(server, dict):
        names = ", ".join(sorted(servers)) or "none"
        return "", "", f"present, but no 'orca-security' server (found: {names})"

    header = (server.get("headers") or {}).get("Authorization", "") or ""
    raw = header.split(None, 1)[1] if header.lower().startswith("token ") else header
    url = (server.get("url") or "").rstrip("/")
    base = url[:-4] if url.endswith("/mcp") else ""
    token = usable(raw)
    if token:
        status = "token found"
    elif header:
        status = "orca-security entry found, but its token is a placeholder"
    else:
        status = "orca-security entry found, but it has no token (OAuth-style MCP config)"
    return token, usable(base), status


def normalize_token(token):
    """Restore stripped base64 padding.

    Orca tokens are base64 and usually end in '='. Several copy paths (some
    terminals, JSON editors, form fields) drop the trailing padding, and Orca
    compares the string literally, so the unpadded value comes back as
    'API Token not found' - which reads as an expired token rather than a
    mangled one. Only pad when the result decodes to the expected
    '<url>||<secret>' shape, so arbitrary tokens are left untouched.
    """
    if not token or token.endswith("="):
        return token
    padded = token + "=" * (-len(token) % 4)
    if padded == token:
        return token
    try:
        decoded = base64.b64decode(padded).decode()
    except Exception:
        return token
    return padded if "||" in decoded else token


def host_from_token(token):
    """Orca tokens are base64 of '<console-url>||<secret>'; map app.* -> api.*"""
    try:
        decoded = base64.b64decode(token + "==" * (-len(token) % 4)).decode()
    except Exception:
        return ""
    if "||" not in decoded:
        return ""
    url = decoded.split("||", 1)[0].rstrip("/")
    return url.replace("://app.", "://api.") if url.startswith("http") else ""


def resolve():
    home = os.path.expanduser("~")
    token = usable(os.environ.get("ORCA_API_TOKEN", ""))
    base = usable(os.environ.get("ORCA_API_BASE", ""))
    source = "$ORCA_API_TOKEN" if token else ""
    checked = []

    if not token:
        for path in (f"{home}/.orca/token", f"{home}/.orca-api-token"):
            found = token_from_file(path)
            checked.append(f"{path}: {'token found' if found else 'absent or unusable'}")
            if found:
                token, source = found, path
                break

    for path in (".mcp.json", f"{home}/.claude/.mcp.json", f"{home}/.mcp.json"):
        if token and base:
            break
        file_token, file_base, status = from_mcp_json(path)
        checked.append(f"{path}: {status}")
        if not token and file_token:
            token, source = file_token, path
        if not base and file_base:
            base = file_base

    token = normalize_token(token)
    host_source = "$ORCA_API_BASE or config" if base else ""
    if token and not base:
        base = host_from_token(token)
        host_source = "derived from the token" if base else ""

    return token, base, source, host_source, checked


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, help="path to write the JSON artifact")
    args = parser.parse_args()

    token, base, source, host_source, checked = resolve()

    if not token or not base:
        print("No usable Orca API credential found.\n")
        print("Checked:")
        for line in checked:
            print(f"  - {line}")
        if token and not base:
            print("\nA token was found but no API host could be determined.")
            print("Set ORCA_API_BASE to your regional Orca API host.")
        else:
            print("\nAn OAuth or connector-based MCP setup authenticates the MCP")
            print("session, which a REST call cannot reuse - so this is expected,")
            print("not a broken configuration.")
            print("\nTo set one up (one command, no region needed):")
            print("  mkdir -p ~/.orca && chmod 700 ~/.orca")
            print("  echo 'YOUR_TOKEN' > ~/.orca/token && chmod 600 ~/.orca/token")
        return 2

    print(f"credential source : {source}")
    print(f"api host          : {base}  ({host_source})")

    request = urllib.request.Request(
        f"{base}/api/iaminator", headers={"Authorization": f"Token {token}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        body = (exc.read() or b"").decode(errors="replace")[:400]
        hint = {
            401: "The token is not valid, is truncated, or has expired. Copy it "
                 "again in full - Orca tokens end in '=' and some copy paths drop it.",
            403: "If the message mentions permissions on Orca's side, this is not "
                 "your token; raise it with Orca.",
            404: f"No endpoint at {base}. Set ORCA_API_BASE to the correct regional host.",
        }.get(exc.code, "Orca-side problem; retry, then raise it with Orca.")
        print(f"HTTP {exc.code} - {hint}")
        if body.strip():
            print(f"response: {body}")
        return 3
    except Exception as exc:
        print(f"could not reach {base}: {exc}")
        return 4

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        print(f"HTTP {status} but the body was not JSON ({len(payload)} bytes)")
        return 3

    with open(args.out, "wb") as handle:
        handle.write(payload)

    print(f"HTTP {status}          : {len(payload)} bytes -> {args.out}")
    if not data:
        print("providers         : none (no clustering produced for this org)")
        return 0
    for provider, value in sorted(data.items()):
        if not isinstance(value, dict):
            print(f"  {provider}: unexpected payload shape")
            continue
        metrics = value.get("general_metrics", {})
        plans = sorted(value.get("plans", {}), key=lambda k: int(k.split("_")[1]))
        print(
            f"  {provider}: shrink_succeed={value.get('shrink_succeed')} "
            f"recommended={metrics.get('recommended_plan')} "
            f"clustered={metrics.get('identities')} plans={plans}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
