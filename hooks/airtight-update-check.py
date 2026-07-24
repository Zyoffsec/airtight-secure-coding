#!/usr/bin/env python3
"""Airtight update check — opt-in, read-only, at most once a week.

Compares the installed skill version against the published one and prints a
single line when a newer release exists. It does not download, install, or
modify anything.

That restraint is deliberate. An auto-updater that pulls remote code and puts it
on the execution path is Gate 93 (code fetched then executed) and Gate 95 (no
signature on the artifact) — the exact supply-chain shape this skill tells you
not to build. A security tool that exempts itself from its own gates is not one.
So this only tells you an update exists; applying it stays a command you type.

Off unless AIRTIGHT_UPDATE_CHECK=on. Never blocks, never raises, never delays
a session by more than the timeout below.
"""
import json
import os
import re
import sys
import time
import urllib.request

VERSION_URL = (
    "https://raw.githubusercontent.com/Zyoffsec/"
    "airtight-secure-coding/main/SKILL.md"
)
INTERVAL = 7 * 24 * 3600          # one check per week
TIMEOUT = 3                       # seconds; a slow network must not stall a session
STAMP = os.path.expanduser("~/.cache/airtight/update-check")
VERSION_RE = re.compile(r"^version:\s*([0-9]+(?:\.[0-9]+)*)\s*$", re.MULTILINE)


def parse(v):
    return tuple(int(p) for p in v.split("."))


def local_version():
    here = os.path.dirname(os.path.abspath(__file__))
    for rel in (os.path.join(os.pardir, "SKILL.md"), "SKILL.md"):
        p = os.path.abspath(os.path.join(here, rel))
        if os.path.isfile(p):
            m = VERSION_RE.search(open(p, encoding="utf-8").read())
            if m:
                return m.group(1)
    return None


def due():
    try:
        return time.time() - os.path.getmtime(STAMP) > INTERVAL
    except OSError:
        return True


def touch():
    os.makedirs(os.path.dirname(STAMP), exist_ok=True)
    with open(STAMP, "w") as fh:
        fh.write(str(int(time.time())))


def main():
    if os.environ.get("AIRTIGHT_UPDATE_CHECK", "").lower() not in ("on", "1", "true"):
        return
    if not due():
        return
    local = local_version()
    if not local:
        return
    touch()                        # stamp first: a failed check waits a week too
    req = urllib.request.Request(VERSION_URL, headers={"User-Agent": "airtight-update-check"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        m = VERSION_RE.search(resp.read(8192).decode("utf-8", "replace"))
    if not m:
        return
    remote = m.group(1)
    if parse(remote) <= parse(local):
        return
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": (
                f"Airtight {remote} is available (installed: {local}). Nothing has been "
                "downloaded or changed. Mention this to the developer once, with the "
                "changelog link, and let them decide:\n"
                "  git -C <skill dir> pull   # or: npx skills add Zyoffsec/airtight-secure-coding\n"
                "  https://github.com/Zyoffsec/airtight-secure-coding/blob/main/CHANGELOG.md"
            ),
        }
    }))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
