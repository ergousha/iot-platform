#!/usr/bin/env bash
# Undoes a kill-switch trip, once you know why it tripped.
#
#   scripts/guard-reset.sh [--yes]
#
# 1. Shows the guard state (scope, since when, why).
# 2. Detaches the deny-all policy from every target except the quarantine
#    group: the fleet groups come back, devices reconnect on their next retry.
# 3. Clears the state, so claim-window.sh works again.
#
# It does not re-activate the claim (INACTIVE is its normal state) and does not
# re-enable the telemetry rules: the next `terraform apply` sets them to the
# configured debug_telemetry_logs value. Needs the owner's AWS credentials and jq.
set -euo pipefail

yes="${1:-}"
if [[ -n "$yes" && "$yes" != "--yes" ]]; then
  echo "usage: $0 [--yes]" >&2
  exit 2
fi

param="${GUARD_STATE_PARAMETER:-/esp32-ztp/guard/state}"
policy="${DENY_POLICY:-esp32-ztp-guard-deny-all}"
quarantine="${QUARANTINE_GROUP:-esp32-ztp-quarantine}"

state=$(aws ssm get-parameter --name "$param" --query Parameter.Value --output text)
echo "guard state:"
jq . <<<"$state"

# The AWS call runs at the top level, where set -e stops the script on a
# failure: bash 3.2 does not apply set -e inside $(...), so a failing call
# hidden in a pipeline or function would look like "nothing attached".
fleet_targets() { # filters list-targets-for-policy text output
  tr '\t' '\n' <<<"$1" | grep -v -e "/${quarantine}\$" -e '^None$' -e '^$' || true
}
all=$(aws iot list-targets-for-policy --policy-name "$policy" --query 'targets' --output text)
targets=$(fleet_targets "$all")
if [[ -n "$targets" ]]; then
  echo "deny-all is attached to:"
  sed 's/^/  /' <<<"$targets"
else
  echo "deny-all is attached to nothing but the quarantine group."
fi

if [[ "$yes" != --yes ]]; then
  read -r -p "Reset the guard? [y/N] " answer
  [[ "$answer" == [yY] ]] || { echo "nothing changed"; exit 1; }
fi

while IFS= read -r target; do
  [[ -z "$target" ]] && continue
  aws iot detach-policy --policy-name "$policy" --target "$target"
  echo "detached deny-all from $target"
done <<<"$targets"

all=$(aws iot list-targets-for-policy --policy-name "$policy" --query 'targets' --output text)
left=$(fleet_targets "$all")
if [[ -n "$left" ]]; then
  echo "deny-all is still attached to: $left; the guard stays tripped" >&2
  exit 1
fi

aws ssm put-parameter --name "$param" --type String --overwrite \
  --value "$(jq -c --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{tripped: false, reset_at: $at, last: del(.last)}' <<<"$state")" >/dev/null
echo "guard reset. Devices reconnect on their next retry; run terraform apply to restore the rules."

# A budget's ACTUAL alert fires once per month: one already over its limit
# only re-alerts at 150 %.
aws budgets describe-budgets --account-id "$(aws sts get-caller-identity --query Account --output text)" \
  --query "Budgets[?starts_with(BudgetName, 'esp32-ztp-guard-')].[BudgetName,CalculatedSpend.ActualSpend.Amount,BudgetLimit.Amount]" \
  --output text | while read -r name spent limit; do
  if awk -v s="$spent" -v l="$limit" 'BEGIN { exit !(s + 0 > l + 0) }'; then
    echo "WARNING: $name is already over its limit (\$$spent of \$$limit) this month; it trips the kill switch again only at 150 %." >&2
  fi
done
