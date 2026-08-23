#!/usr/bin/env bash
#
# refresh-specs.sh — refresh the cached specification corpus under specs/.
#
# The roster is specs/manifest.tsv (committed). This script is a dumb executor
# over its rows: it fetches each url, validates the response, converts HTML/PDF
# sources to text, and rewrites the manifest with fresh hashes and validators.
#
# Adding a spec means appending a manifest row with id, title, url, fidelity and
# path, leaving the origin_sha256/origin_bytes/validator/fetched columns as "-",
# then re-running this script.
#
# Like scripts/update-geoip.sh, this is a refresh tool whose output is committed
# rather than something the build runs. specs/manifest.tsv, not this file, is the
# roster: the corpus stays reproducible from the manifest alone.
#
# Usage:
#   scripts/refresh-specs.sh              refresh everything that changed upstream
#   scripts/refresh-specs.sh --check      report upstream drift, write nothing
#   scripts/refresh-specs.sh --reconcile  list RFCs cited in code but not cached
#
# Requires: curl, jq, shasum, textutil (macOS, HTML), pdftotext (poppler, PDF).

set -euo pipefail

readonly ERRATA_URL="https://www.rfc-editor.org/api/v1/errata.json"
# Smallest real document in the corpus is RFC 2606 at 8008 bytes; the openid.net
# meta-refresh stub is 605. Anything under this floor is an error page.
readonly MIN_BYTES=2000
readonly CURL_TIMEOUT=180

MODE="refresh"
REPO_ROOT=""
MANIFEST=""
TMPDIR_RUN=""
TODAY=""

n_updated=0
n_unchanged=0
n_rejected=0

log() { printf '%s\n' "$*" >&2; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  [ -n "$TMPDIR_RUN" ] && [ -d "$TMPDIR_RUN" ] && rm -rf "$TMPDIR_RUN"
}

preflight() {
  local tool missing=""
  for tool in curl jq shasum textutil pdftotext perl; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
  done
  [ -z "$missing" ] || die "missing required tools:$missing"

  REPO_ROOT=$(git rev-parse --show-toplevel) ||
    die "not inside a git repository"
  MANIFEST="$REPO_ROOT/specs/manifest.tsv"
  [ -f "$MANIFEST" ] || die "roster not found: $MANIFEST"
  TODAY=$(date -u +%Y-%m-%d)
}

# Emit the provenance banner for a converted file. Converted text is not
# byte-identical to the source, so the banner records what it came from and
# marks it non-authoritative for load-bearing quotes.
banner() {
  local title="$1" url="$2" ct="$3" tool="$4" bytes="$5" sha="$6"
  cat <<BANNER
================================================================================
CACHED SPEC - CONVERTED, NOT AUTHORITATIVE
  Title:         $title
  Source:        $url
  Conversion:    $ct -> text/plain via $tool
  Origin bytes:  $bytes
  Origin sha256: $sha
  Fetched:       $TODAY

Section structure and prose are preserved; exact formatting is not. Confirm any
load-bearing quote against the Source URL before citing it. Verbatim specs under
specs/rfc/, specs/ietf-drafts/ and the .txt entries in specs/openid/ carry no
banner and are byte-identical to their origin.
================================================================================

BANNER
}

# Reject a response that reached us but is not the document we asked for. The
# three observed traps: openid.net answers 404 with a 122KB HTML body, OASIS
# answers 404 with 41KB, and openid.net answers 200 with a 605-byte
# meta-refresh stub for renamed FAPI specs.
validate_body() {
  local body="$1" fidelity="$2" ct="$3" size="$4"

  if [ "$size" -lt "$MIN_BYTES" ]; then
    log "  rejected: body is $size bytes, below the $MIN_BYTES floor"
    return 1
  fi

  if head -c 4096 "$body" | LC_ALL=C grep -qi 'http-equiv=.\{0,2\}refresh'; then
    log "  rejected: body is a meta-refresh stub, not the specification"
    return 1
  fi

  case "$fidelity" in
  verbatim)
    if [ "$ct" != "text/plain" ]; then
      log "  rejected: fidelity is verbatim but content-type is $ct"
      return 1
    fi
    ;;
  converted)
    case "$ct" in
    text/html | application/pdf) ;;
    *)
      log "  rejected: fidelity is converted but content-type is $ct"
      return 1
      ;;
    esac
    ;;
  *)
    log "  rejected: unknown fidelity '$fidelity'"
    return 1
    ;;
  esac
  return 0
}

# text/plain is copied byte-for-byte. HTML and PDF are converted and stripped of
# page-break control characters and textutil's injected pilcrow markers; no text
# lines are removed, so nothing normative can be lost to the cleanup.
convert_body() {
  local body="$1" ct="$2" out="$3"
  local staged="$TMPDIR_RUN/converted.txt"

  case "$ct" in
  text/plain)
    cp "$body" "$out"
    ;;
  text/html)
    textutil -convert txt -format html -stdin -stdout <"$body" >"$staged"
    LC_ALL=C tr -d '\f\r' <"$staged" | perl -CSD -pe 's/\x{00B6}//g' >"$out"
    ;;
  application/pdf)
    pdftotext -layout "$body" "$staged"
    LC_ALL=C tr -d '\f\r' <"$staged" >"$out"
    ;;
  *)
    return 1
    ;;
  esac
  return 0
}

conversion_tool() {
  case "$1" in
  text/html) printf 'textutil' ;;
  application/pdf) printf 'pdftotext -layout' ;;
  *) printf 'copy' ;;
  esac
}

# Walk the roster. Each row is refreshed independently; a rejected row keeps its
# existing file and manifest values so one bad origin cannot corrupt the corpus.
refresh_rows() {
  local out_manifest="$TMPDIR_RUN/manifest.new"
  local body="$TMPDIR_RUN/body.bin"
  local id title url fidelity sha bytes validator fetched path
  local meta code ct etag lm size new_sha new_validator target tool
  local -a cond

  head -n 1 "$MANIFEST" >"$out_manifest"

  while IFS=$'\t' read -r id title url fidelity sha bytes validator fetched path <&3; do
    [ "$id" = "id" ] && continue
    [ -n "$id" ] || continue

    target="$REPO_ROOT/$path"
    cond=()
    # Only honour a 304 when the file is actually on disk; otherwise a cached
    # validator would skip a fetch we need.
    if [ -f "$target" ]; then
      case "$validator" in
      etag:*) cond=(-H "If-None-Match: ${validator#etag:}") ;;
      lastmod:*) cond=(-H "If-Modified-Since: ${validator#lastmod:}") ;;
      esac
    fi

    if meta=$(curl -sSL --max-time "$CURL_TIMEOUT" --retry 2 --retry-delay 2 \
      -o "$body" \
      -w '%{http_code}\t%{content_type}\t%header{etag}\t%header{last-modified}' \
      ${cond[@]+"${cond[@]}"} "$url" </dev/null); then
      :
    else
      log "$id: curl failed"
      n_rejected=$((n_rejected + 1))
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$id" "$title" "$url" "$fidelity" "$sha" "$bytes" "$validator" "$fetched" "$path" \
        >>"$out_manifest"
      continue
    fi

    code=$(printf '%s' "$meta" | cut -f1)
    ct=$(printf '%s' "$meta" | cut -f2 | cut -d';' -f1)
    etag=$(printf '%s' "$meta" | cut -f3)
    lm=$(printf '%s' "$meta" | cut -f4)

    if [ "$code" = "304" ]; then
      n_unchanged=$((n_unchanged + 1))
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$id" "$title" "$url" "$fidelity" "$sha" "$bytes" "$validator" "$fetched" "$path" \
        >>"$out_manifest"
      continue
    fi

    if [ "$code" != "200" ]; then
      log "$id: HTTP $code"
      n_rejected=$((n_rejected + 1))
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$id" "$title" "$url" "$fidelity" "$sha" "$bytes" "$validator" "$fetched" "$path" \
        >>"$out_manifest"
      continue
    fi

    size=$(wc -c <"$body" | tr -d ' ')
    if ! validate_body "$body" "$fidelity" "$ct" "$size"; then
      log "$id: response rejected"
      n_rejected=$((n_rejected + 1))
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$id" "$title" "$url" "$fidelity" "$sha" "$bytes" "$validator" "$fetched" "$path" \
        >>"$out_manifest"
      continue
    fi

    # The hash always covers the origin bytes, never the converted output, so a
    # cached file can be re-verified against its source.
    new_sha=$(shasum -a 256 "$body" | awk '{print $1}')
    if [ -n "$etag" ]; then
      new_validator="etag:$etag"
    elif [ -n "$lm" ]; then
      new_validator="lastmod:$lm"
    else
      new_validator="-"
    fi

    if [ "$new_sha" = "$sha" ] && [ -f "$target" ]; then
      n_unchanged=$((n_unchanged + 1))
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$id" "$title" "$url" "$fidelity" "$new_sha" "$size" "$new_validator" "$fetched" "$path" \
        >>"$out_manifest"
      continue
    fi

    if [ "$MODE" = "check" ]; then
      log "$id: DRIFT - origin changed ($url)"
      n_updated=$((n_updated + 1))
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$id" "$title" "$url" "$fidelity" "$sha" "$bytes" "$validator" "$fetched" "$path" \
        >>"$out_manifest"
      continue
    fi

    mkdir -p "$(dirname "$target")"
    if [ "$fidelity" = "converted" ]; then
      tool=$(conversion_tool "$ct")
      convert_body "$body" "$ct" "$TMPDIR_RUN/clean.txt" ||
        die "$id: conversion failed for $ct"
      {
        banner "$title" "$url" "$ct" "$tool" "$size" "$new_sha"
        cat "$TMPDIR_RUN/clean.txt"
      } >"$target"
    else
      convert_body "$body" "$ct" "$target" || die "$id: copy failed"
    fi

    log "$id: updated ($size bytes)"
    n_updated=$((n_updated + 1))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$id" "$title" "$url" "$fidelity" "$new_sha" "$size" "$new_validator" "$TODAY" "$path" \
      >>"$out_manifest"
  done 3<"$MANIFEST"

  if [ "$MODE" = "refresh" ]; then
    mv "$out_manifest" "$MANIFEST"
  fi
}

# There is no per-RFC errata endpoint: /api/v1/errata/?rfc=N is 404 and
# errata_search.php ignores &format=csv. Fetch the global dump once and shard it
# in a single jq pass rather than re-parsing it per RFC.
refresh_errata() {
  local dump="$TMPDIR_RUN/errata.json"
  local wanted="$TMPDIR_RUN/wanted.txt"
  local doc_id payload num out n_shards=0

  awk -F'\t' 'NR>1 && $1 ~ /^rfc[0-9]+$/ {print toupper($1)}' "$MANIFEST" >"$wanted"

  log "fetching global errata dump..."
  curl -sSL --max-time "$CURL_TIMEOUT" -o "$dump" "$ERRATA_URL" </dev/null ||
    die "errata dump fetch failed"
  jq -e 'type == "array"' "$dump" >/dev/null ||
    die "errata dump is not a JSON array"

  # Clear stale shards only. Deleting the directory outright would take anything
  # else that happens to be in the tree with it.
  mkdir -p "$REPO_ROOT/specs/rfc/errata"
  find "$REPO_ROOT/specs/rfc/errata" -maxdepth 1 -name '*.json' -delete

  while IFS=$'\t' read -r doc_id payload; do
    grep -qxF "$doc_id" "$wanted" || continue
    num=$(printf '%s' "$doc_id" | tr '[:upper:]' '[:lower:]')
    out="$REPO_ROOT/specs/rfc/errata/$num.json"
    printf '%s' "$payload" | jq '.' >"$out"
    n_shards=$((n_shards + 1))
  done < <(jq -r 'group_by(."doc-id")[] | "\(.[0]."doc-id")\t\(tojson)"' "$dump")

  log "errata: wrote $n_shards shards"
}

# git grep only searches tracked files. A plain grep -r would pick up
# fuzz/target/ dependency metadata and report phantom RFCs the code never
# implements (5280 x190, 3526 x120, 7919 x78).
reconcile() {
  local cited cached missing
  cited="$TMPDIR_RUN/cited.txt"
  cached="$TMPDIR_RUN/cached.txt"

  git -C "$REPO_ROOT" grep -ohIE 'RFC ?-?[0-9]{3,4}' -- ':!specs/' |
    grep -oE '[0-9]{3,4}' | sort -un >"$cited"
  awk -F'\t' 'NR>1 && $1 ~ /^rfc[0-9]+$/ {print substr($1,4)}' "$MANIFEST" |
    sort -un >"$cached"

  missing=$(comm -23 "$cited" "$cached")
  if [ -z "$missing" ]; then
    log "reconcile: every RFC cited in tracked source is cached"
    return 0
  fi
  log "reconcile: cited in source but not cached:"
  printf '%s\n' "$missing" | sed 's/^/  RFC /' >&2
  return 1
}

main() {
  case "${1:-}" in
  --check) MODE="check" ;;
  --reconcile) MODE="reconcile" ;;
  "") MODE="refresh" ;;
  *) die "unknown argument: $1 (expected --check, --reconcile, or nothing)" ;;
  esac

  preflight
  TMPDIR_RUN=$(mktemp -d)
  trap cleanup EXIT

  if [ "$MODE" = "reconcile" ]; then
    reconcile
    return $?
  fi

  refresh_rows

  if [ "$MODE" = "check" ]; then
    log "check: $n_updated drifted, $n_unchanged current, $n_rejected rejected"
    { [ "$n_updated" -eq 0 ] && [ "$n_rejected" -eq 0 ]; } || return 1
    return 0
  fi

  refresh_errata
  log "refresh: $n_updated updated, $n_unchanged unchanged, $n_rejected rejected"
  [ "$n_rejected" -eq 0 ] || return 1
  return 0
}

main "$@"
