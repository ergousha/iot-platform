#!/usr/bin/env bash
# Opens a timed enrolment window: activates the shared claim certificate, waits,
# and deactivates it again when the time is up, on Ctrl-C, or on any exit.
#
#   scripts/claim-window.sh [minutes]     (default 30, at most 120)
#
# Superseded by `ergo commission` (iot-device-sdk), which arms and disarms the
# claim itself; kept for a manual enrolment. The claim is INACTIVE the rest of
# the time. The OTA controller's tick (every 15 min) disarms it unless a
# registry record has an open window (allowed=true, provisioned=false,
# enrol_by in the future), so register the device first (`ergo register`),
# then run this and power the device: it enrols with the claim within a
# minute or two and from then on uses its own certificate.
#
# Uses the caller's AWS credentials (the owner's), not anything in the repo,
# and jq.
set -euo pipefail

minutes="${1:-30}"
# No leading zero: bash would read 010 as octal.
if ! [[ "$minutes" =~ ^[1-9][0-9]{0,2}$ ]] || ((minutes > 120)); then
  echo "usage: $0 [minutes 1-120]" >&2
  exit 2
fi

policy="${CLAIM_POLICY:-esp32-ztp-claim-policy}"

# Never open a window while the kill switch has tripped: something is abusing
# the platform. scripts/guard-reset.sh clears the trip once it is understood.
state=$(aws ssm get-parameter --name "${GUARD_STATE_PARAMETER:-/esp32-ztp/guard/state}" --query Parameter.Value --output text)
if [[ "$(jq -r '.tripped' <<<"$state")" != false ]]; then
  echo "refusing: the guard is tripped: $state" >&2
  echo "investigate, then run scripts/guard-reset.sh" >&2
  exit 1
fi

# The claim certificate is the one target of the claim policy.
targets=$(aws iot list-targets-for-policy --policy-name "$policy" --query 'targets' --output text)
count=$(wc -w <<<"$targets" | tr -d ' ')
if [[ "$count" != 1 ]]; then
  echo "expected exactly one certificate on $policy, found $count: $targets" >&2
  exit 1
fi
cert_id="${targets##*/}"

close_window() {
  # A second Ctrl-C must not kill the deactivation call itself.
  trap '' INT TERM HUP
  if aws iot update-certificate --certificate-id "$cert_id" --new-status INACTIVE; then
    echo "$(date '+%H:%M:%S') claim INACTIVE again."
  else
    echo "!! could not deactivate the claim ${cert_id:0:12}; run:" >&2
    echo "   aws iot update-certificate --certificate-id $cert_id --new-status INACTIVE" >&2
  fi
}
trap close_window EXIT
trap 'exit 130' INT TERM HUP

aws iot update-certificate --certificate-id "$cert_id" --new-status ACTIVE
echo "$(date '+%H:%M:%S') claim ${cert_id:0:12} ACTIVE for $minutes min. Power the device now; Ctrl-C closes the window early."
# Wall-clock deadline: a single long sleep would not count the time a laptop
# spends asleep, keeping the window open longer than asked.
deadline=$(($(date +%s) + minutes * 60))
while (($(date +%s) < deadline)); do
  sleep 5
done
