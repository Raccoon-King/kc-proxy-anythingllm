#!/bin/sh
set -eu

BASE_URL="${BASE_URL:-http://localhost:8080}"

expect_code() {
  url="$1"
  code="$2"
  got="$(curl -s -o /dev/null -w "%{http_code}" "$url")"
  if [ "$got" != "$code" ]; then
    echo "FAIL: $url expected $code got $got"
    exit 1
  fi
  echo "OK: $url -> $got"
}

expect_redirect_contains() {
  url="$1"
  needle="$2"
  loc="$(curl -s -o /dev/null -w "%{redirect_url}" -L -I "$url")"
  case "$loc" in
    *"$needle"*) echo "OK: $url redirect contains $needle" ;;
    *) echo "FAIL: $url redirect missing $needle (got $loc)"; exit 1 ;;
  esac
}

expect_code "$BASE_URL/healthz" "200"
expect_code "$BASE_URL/manifest.json" "200"
expect_redirect_contains "$BASE_URL/login" "/protocol/openid-connect/auth"
expect_redirect_contains "$BASE_URL/sso/simple" "/protocol/openid-connect/logout"

echo "Smoke tests passed."
