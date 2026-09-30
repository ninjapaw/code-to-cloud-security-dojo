#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node_command="${NODE_COMMAND:-}"
if [[ -z "$node_command" ]]; then
    for candidate in node node.exe '/c/Program Files/nodejs/node.exe'; do
        if command -v "$candidate" >/dev/null 2>&1; then node_command="$candidate"; break; fi
    done
fi
[[ -n "$node_command" ]] || { printf '%s\n' 'Node.js 22+ is required.' >&2; exit 1; }
exec "$node_command" scripts/deploy.mjs "$@"