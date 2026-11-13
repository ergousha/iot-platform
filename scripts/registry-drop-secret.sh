#!/usr/bin/env bash
# One-off registry cleanup for plan Phase 6 (enforce), before its
# `terraform apply`. The hook no longer has a shared-secret path and no
# legacy product, so:
#
# 1. every record loses its `secret` (the gateway's shared DEVICE_SECRET,
#    public since it was compiled into every gateway image);
# 2. every record without `product` (written by hand before products
#    existed) gets the product that used to own such records, `gateway`.
#    Without it the controller and the portal would no longer count the
#    record as anyone's.
#
#   scripts/registry-drop-secret.sh           show what would change
#   scripts/registry-drop-secret.sh --apply   change it (asks once more)
#
# Needs the owner's AWS credentials and jq.
set -euo pipefail

mode="${1:-}"
[[ -z "$mode" || "$mode" == --apply ]] || { echo "usage: $0 [--apply]" >&2; exit 2; }

table="${REGISTRY_TABLE:-esp32-ztp-device-registry}"
legacy_product="${LEGACY_PRODUCT:-gateway}"

items=$(aws dynamodb scan --table-name "$table" \
  --projection-expression "mac_address, #p, #s" \
  --expression-attribute-names '{"#p":"product","#s":"secret"}' \
  --output json |
  jq -c '[.Items[] | select(.product == null or .secret != null)
          | {mac: .mac_address.S, product: (.product.S // null), secret: (.secret != null)}]')
count=$(jq length <<<"$items")
echo "registry $table: $count record(s) to change"
jq -r --arg p "$legacy_product" '.[] |
  "  \(.mac):" +
  (if .secret then " remove secret;" else "" end) +
  (if .product == null then " set product=\($p)" else "" end)' <<<"$items"

((count > 0)) || exit 0
if [[ "$mode" != --apply ]]; then
  echo "dry run; --apply changes the above"
  exit 0
fi
read -r -p "Change them? [y/N] " answer
[[ "$answer" == [yY] ]] || { echo "nothing changed"; exit 1; }

for mac in $(jq -r '.[].mac' <<<"$items"); do
  aws dynamodb update-item --table-name "$table" \
    --key "$(jq -nc --arg m "$mac" '{mac_address: {S: $m}}')" \
    --update-expression "SET #p = if_not_exists(#p, :p) REMOVE #s" \
    --condition-expression "attribute_exists(mac_address)" \
    --expression-attribute-names '{"#p":"product","#s":"secret"}' \
    --expression-attribute-values "$(jq -nc --arg p "$legacy_product" '{":p": {S: $p}}')"
  echo "  $mac done"
done
echo "done. No record carries a shared secret; every record names its product."
