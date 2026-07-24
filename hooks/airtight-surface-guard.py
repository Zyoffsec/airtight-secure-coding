#!/usr/bin/env python3
"""Airtight surface guard — launcher.

A PreToolUse hook runs on every file write the assistant makes. If it raises, the
developer sees a hook error in the middle of their work, and a security tool that
breaks the session it was meant to protect has spent its credibility.

So this file holds no logic. It reads stdin, hands it to `airtight_guard_impl`,
and swallows everything that can go wrong — including a SyntaxError in the
implementation, which an import raises at runtime and this try/except therefore
catches. The implementation can be edited, broken, or deleted outright; the worst
outcome is a write that passes unchecked.

Keep it that way. Logic added here is logic that can take the session down.

    --selftest   run the implementation's regression suite and report

Off entirely with AIRTIGHT_GUARD=off. Advisory gate context, which costs tokens on
every write touching a security surface, is off unless AIRTIGHT_GUARD=verbose;
denials always fire.
"""
import os
import sys

MAX_STDIN = 4_000_000


def main():
    if os.environ.get("AIRTIGHT_GUARD", "").lower() in ("off", "0", "false", "no"):
        return
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import airtight_guard_impl as impl

    if "--selftest" in sys.argv:
        impl.selftest()
        return

    impl.run(sys.stdin.read(MAX_STDIN))


if __name__ == "__main__":
    try:
        main()
    except BaseException:          # noqa: BLE001 — a guard must not break the session
        pass
    sys.exit(0)
