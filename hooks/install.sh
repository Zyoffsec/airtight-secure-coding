#!/usr/bin/env bash
# Wire the Airtight guard into Claude Code.
#
# Idempotent: run it twice and the second run changes nothing. It backs the
# settings file up before touching it, never removes a hook it did not add, and
# verifies the guard with its own self-test before reporting success.
#
#   ./hooks/install.sh            # install or repair
#   ./hooks/install.sh --uninstall
#   ./hooks/install.sh --with-update-check
set -euo pipefail

HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$HOOK_DIR/airtight-surface-guard.py"
UPDATE="$HOOK_DIR/airtight-update-check.py"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
MODE="install"
WITH_UPDATE="no"

for arg in "$@"; do
  case "$arg" in
    --uninstall) MODE="uninstall" ;;
    --with-update-check) WITH_UPDATE="yes" ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
[ -f "$GUARD" ] || { echo "guard not found at $GUARD" >&2; exit 1; }

if [ "$MODE" = "install" ]; then
  echo "Verifying the guard before wiring it in..."
  python3 "$GUARD" --selftest || { echo "self-test failed — not installing" >&2; exit 1; }
  echo
fi

mkdir -p "$(dirname "$SETTINGS")"
[ -f "$SETTINGS" ] || echo '{}' > "$SETTINGS"
BACKUP="$SETTINGS.airtight-backup.$(date +%Y%m%d%H%M%S)"
cp "$SETTINGS" "$BACKUP"

MODE="$MODE" WITH_UPDATE="$WITH_UPDATE" GUARD="$GUARD" UPDATE="$UPDATE" \
SETTINGS="$SETTINGS" BACKUP="$BACKUP" python3 <<'PY'
import json, os, sys

settings_path = os.environ["SETTINGS"]
guard_cmd = f'python3 "{os.environ["GUARD"]}"'
update_cmd = f'AIRTIGHT_UPDATE_CHECK=on python3 "{os.environ["UPDATE"]}"'
uninstalling = os.environ["MODE"] == "uninstall"

try:
    with open(settings_path) as fh:
        settings = json.load(fh)
except json.JSONDecodeError as exc:
    sys.exit(f"{settings_path} is not valid JSON ({exc}); fix it before running this.")

hooks = settings.setdefault("hooks", {})
changed = []


def entries(event):
    return hooks.setdefault(event, [])


def find(event, needle):
    for group in entries(event):
        for hook in group.get("hooks", []):
            if needle in hook.get("command", ""):
                return group, hook
    return None, None


def drop(event, needle, label):
    global changed
    for group in list(entries(event)):
        before = len(group.get("hooks", []))
        group["hooks"] = [h for h in group.get("hooks", []) if needle not in h.get("command", "")]
        if len(group["hooks"]) != before:
            changed.append(f"removed {label}")
        if not group["hooks"]:
            entries(event).remove(group)
    if not entries(event):
        hooks.pop(event, None)


if uninstalling:
    drop("PreToolUse", "airtight-surface-guard", "the guard")
    drop("SessionStart", "airtight-update-check", "the update check")
else:
    group, hook = find("PreToolUse", "airtight-surface-guard")
    if hook is None:
        entries("PreToolUse").append({
            "matcher": "Write|Edit|MultiEdit",
            "hooks": [{"type": "command", "command": guard_cmd}],
        })
        changed.append("added the guard on Write|Edit|MultiEdit")
    elif hook["command"] != guard_cmd:
        hook["command"] = guard_cmd
        changed.append("repointed the guard at this checkout")

    if os.environ["WITH_UPDATE"] == "yes":
        _, existing = find("SessionStart", "airtight-update-check")
        if existing is None:
            entries("SessionStart").append({"hooks": [{"type": "command", "command": update_cmd}]})
            changed.append("added the weekly update check")

if not changed:
    os.remove(os.environ["BACKUP"])
    print("Already configured — nothing to change.")
    sys.exit(0)

tmp = settings_path + ".airtight-tmp"
with open(tmp, "w") as fh:
    json.dump(settings, fh, indent=2)
    fh.write("\n")
os.replace(tmp, settings_path)          # atomic: no half-written settings file
for line in changed:
    print(f"  {line}")
print(f"\nBacked up the previous settings to {os.environ['BACKUP']}")
PY

if [ "$MODE" = "install" ]; then
  cat <<'DONE'

Done. Start a new Claude Code session for it to take effect.

  Turn it off for one run:   AIRTIGHT_GUARD=off claude
  See the gate context too:  AIRTIGHT_GUARD=verbose claude
  Re-check the guard:        ./hooks/install.sh   (it self-tests first)
DONE
fi
