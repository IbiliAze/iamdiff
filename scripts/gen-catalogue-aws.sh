#!/usr/bin/env bash
# Regenerate the embedded AWS action catalogue.
#
# Source of truth is the AWS Service Authorization Reference. Rather than
# scraping it directly, use the community dump that already does so and
# is regenerated automatically.
set -euo pipefail

OUT="${1:-internal/provider/aws/data/catalogue.json}"
SRC="https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/map.json"

echo "fetching ${SRC}"
curl -sfL "$SRC" -o /tmp/iam-dataset.json

jq --arg version "$(date -u +%Y-%m-%d)" '
  {
    version: $version,
    actions: [
      .sdk_permissionless_actions // empty,
      (.sdk_method_iam_mappings // {} | to_entries[] | .value[]? | .action)
    ] | flatten | unique | map({name: ., level: "Unknown"})
  }
' /tmp/iam-dataset.json > "$OUT"

echo "wrote $(jq '.actions | length' "$OUT") actions to ${OUT}"
