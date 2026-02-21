#!/bin/sh
set -eu

if [ -n "${PORT:-}" ]; then
  export GF_SERVER_HTTP_PORT="${PORT}"
fi

exec /run.sh
