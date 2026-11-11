#!/usr/bin/env bash
# Owner overrides of the OTA controller (the portal will offer the same).
#
#   scripts/ota.sh status   <product>
#   scripts/ota.sh promote  <product> [X.Y.Z]   fleet job now, skipping the soak gate
#   scripts/ota.sh hold     <product>           canary and soak, but email instead of promoting
#   scripts/ota.sh resume   <product>           back to auto
#   scripts/ota.sh freeze   <product>           the controller leaves the product alone
#   scripts/ota.sh rerun    <product> [X.Y.Z]   run the canary again (clears that version's halt)
#   scripts/ota.sh rollback <product> X.Y.Z     downgrade the fleet to a verified version (then on hold)
#   scripts/ota.sh target   <product> <thing> [X.Y.Z]   one device: back from excluded, own job
#   scripts/ota.sh rotate-claim                 new claim certificate now
#   scripts/ota.sh tick                         reconcile now instead of at the next quarter hour
#
# Invokes the controller Lambda with the caller's AWS credentials (the
# owner's); only verified (signed) releases are ever rolled out, and only
# rollback downgrades. Needs jq.
set -euo pipefail

function_name="${OTA_CONTROLLER:-esp32-ztp-ota-controller}"
usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

action="${1:-}"
version_re='^[0-9]+\.[0-9]+\.[0-9]+$'
product_re='^[a-z][a-z0-9]{1,15}$'
case "$action" in
  tick | rotate-claim)
    [[ $# -eq 1 ]] || usage
    payload=$(jq -cn --arg a "$action" '{action: $a}')
    ;;
  status | hold | resume | freeze)
    [[ $# -eq 2 && "$2" =~ $product_re ]] || usage
    payload=$(jq -cn --arg a "$action" --arg p "$2" '{action: $a, product: $p}')
    ;;
  promote | rerun | rollback)
    [[ ($# -eq 2 || $# -eq 3) && "$2" =~ $product_re ]] || usage
    [[ $# -eq 2 || "$3" =~ $version_re ]] || usage
    [[ "$action" != rollback || $# -eq 3 ]] || usage
    payload=$(jq -cn --arg a "$action" --arg p "$2" --arg v "${3:-}" '{action: $a, product: $p} + (if $v == "" then {} else {version: $v} end)')
    ;;
  target)
    [[ ($# -eq 3 || $# -eq 4) && "$2" =~ $product_re && "$3" =~ ^[A-Za-z0-9_:-]{1,128}$ ]] || usage
    [[ $# -eq 3 || "$4" =~ $version_re ]] || usage
    payload=$(jq -cn --arg p "$2" --arg t "$3" --arg v "${4:-}" '{action: "target", product: $p, thing: $t} + (if $v == "" then {} else {version: $v} end)')
    ;;
  *) usage ;;
esac

out=$(mktemp)
trap 'rm -f "$out"' EXIT
aws lambda invoke --function-name "$function_name" --cli-binary-format raw-in-base64-out \
  --cli-read-timeout 130 --payload "$payload" "$out" >/dev/null
jq . "$out"
jq -e '.ok == true' "$out" >/dev/null
