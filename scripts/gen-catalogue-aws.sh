#!/usr/bin/env bash
# Regenerate the embedded AWS action catalogue.
#
# Source of truth is the AWS Service Authorization Reference. Rather than
# scraping it directly, use the community dataset that already does so and
# is regenerated daily (MIT): https://github.com/iann0036/iam-dataset
#
# Usage: scripts/gen-catalogue-aws.sh [OUT] 
#   IAM_DATASET_FILE=path   use a local copy instead of downloading
#   CATALOGUE_VERSION=str   override the version stamp (default: UTC date)
set -euo pipefail

OUT="${1:-internal/provider/aws/data/catalogue.json}"
SRC="https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/iam_definition.json"
VERSION="${CATALOGUE_VERSION:-$(date -u +%Y-%m-%d)}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [ -n "${IAM_DATASET_FILE:-}" ]; then
  cp "$IAM_DATASET_FILE" "$tmp/iam_definition.json"
else
  echo "fetching ${SRC}" >&2
  curl -sfL "$SRC" -o "$tmp/iam_definition.json"
fi

# One action per line so a refresh diff reads as added and removed actions
# rather than one rewritten blob. Access levels collapse onto the
# catalogue's vocabulary; the dataset reports combinations such as
# "Permissions management, Write", and the more dangerous half wins.
# Actions that differ only by case are collapsed, preferring the entry
# that carries a level.
{
  printf '{"version":"%s","actions":[\n' "$VERSION"
  jq -r '
    def level:
      if . == null or . == "" then "Unknown"
      elif test("Permissions management") then "PermissionsManagement"
      elif test("Write") then "Write"
      elif . == "Read" or . == "List" or . == "Tagging" then .
      else "Unknown" end;
    [ .[] | .prefix as $p | .privileges[]
      | {name: ($p + ":" + .privilege), level: (.access_level | level)} ]
    | group_by(.name | ascii_downcase)
    | map((map(select(.level != "Unknown")) + .) | .[0])
    | sort_by(.name)
    | .[] | @json
  ' "$tmp/iam_definition.json" | sed '$!s/$/,/'
  printf ']}\n'
} > "$tmp/catalogue.json"

jq -e '.actions | length > 10000' "$tmp/catalogue.json" >/dev/null \
  || { echo "refusing to write a catalogue with suspiciously few actions" >&2; exit 1; }

mv "$tmp/catalogue.json" "$OUT"
echo "wrote $(jq '.actions | length' "$OUT") actions (version ${VERSION}) to ${OUT}" >&2
