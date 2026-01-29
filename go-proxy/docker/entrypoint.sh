#!/bin/sh
set -eu

DEFAULT_ENV="/app/config/default.env"
if [ -f "$DEFAULT_ENV" ]; then
  # shellcheck disable=SC1090
  . "$DEFAULT_ENV"
fi

exec /usr/local/bin/anythingllm-proxy
