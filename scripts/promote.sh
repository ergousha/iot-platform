#!/usr/bin/env bash
# Promotes a product's newest canary release to its whole fleet.
#
#   scripts/promote.sh <product> [--force]
#
# Every firmware upload creates an OTA job for the product's CANARY group (the
# ota_trigger Lambda). Once the canary devices succeeded, this creates the same
# job (same document, presigning, rollout, abort and timeout settings) for the
# FLEET group, and cancels the product's older fleet jobs. Canary devices are in
# the fleet group too; they already run the version and settle it without a
# download.
#
# It refuses while a canary execution is queued, in progress or failed, unless
# --force. Needs the owner's AWS credentials and `terraform` state access (for
# the group names), plus jq.
set -euo pipefail

product="${1:-}"
force="${2:-}"
if ! [[ "$product" =~ ^[a-z][a-z0-9]{1,15}$ ]] || [[ -n "$force" && "$force" != "--force" ]]; then
  echo "usage: $0 <product> [--force]" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
groups=$(terraform output -json canary_thing_groups)
if ! canary_group=$(jq -er --arg p "$product" '.[$p]' <<<"$groups"); then
  echo "unknown product $product (known: $(jq -r 'keys | join(", ")' <<<"$groups"))" >&2
  exit 2
fi
fleet_group=$(terraform output -json fleet_thing_groups | jq -er --arg p "$product" '.[$p]')
canary_arn=$(aws iot describe-thing-group --thing-group-name "$canary_group" --query thingGroupArn --output text)
fleet_arn=$(aws iot describe-thing-group --thing-group-name "$fleet_group" --query thingGroupArn --output text)

# ListJobs on the canary group also returns jobs aimed at its parent (the fleet
# group); keep only jobs that target the canary group itself.
canary_job=""
newest_ts=0
for id in $(aws iot list-jobs --thing-group-name "$canary_group" --status IN_PROGRESS \
  --query "jobs[?starts_with(jobId, 'ota-${product}-')].jobId" --output text); do
  targets=$(aws iot describe-job --job-id "$id" --query 'job.targets' --output json)
  if jq -e --arg a "$canary_arn" 'index($a) != null' <<<"$targets" >/dev/null; then
    ts="${id##*-}"
    if [[ "$ts" =~ ^[0-9]+$ ]] && ((ts > newest_ts)); then
      newest_ts=$ts
      canary_job=$id
    fi
  fi
done
if [[ -z "$canary_job" ]]; then
  echo "no in-progress canary job for $product on $canary_group" >&2
  exit 1
fi

job=$(aws iot describe-job --job-id "$canary_job" --output json)
stats=$(jq -c '.job.jobProcessDetails' <<<"$job")
echo "canary job $canary_job: $stats"
ok=$(jq -r '((.numberOfSucceededThings // 0) >= 1)
  and ((.numberOfQueuedThings // 0) + (.numberOfInProgressThings // 0) + (.numberOfFailedThings // 0)
       + (.numberOfRejectedThings // 0) + (.numberOfTimedOutThings // 0) + (.numberOfCanceledThings // 0)
       + (.numberOfRemovedThings // 0) == 0)' <<<"$stats")
if [[ "$ok" != true && "$force" != --force ]]; then
  echo "refusing: the canary has not succeeded cleanly (use --force to promote anyway)" >&2
  exit 1
fi

# Same ID shape as the Lambda's (ota-<product>-<version>-<ms>). The Lambda only
# supersedes jobs that target the canary group, so this one stays until the
# next promotion replaces it.
fleet_job="${canary_job%-*}-$(($(date +%s) * 1000))"
document=$(aws iot get-job-document --job-id "$canary_job" --query document --output text)

input=$(jq -n --arg id "$fleet_job" --arg target "$fleet_arn" --arg doc "$document" \
  --arg desc "Promoted from $canary_job" --argjson j "$(jq '.job' <<<"$job")" '{
    jobId: $id, targets: [$target], document: $doc, description: $desc,
    targetSelection: "CONTINUOUS",
    presignedUrlConfig: $j.presignedUrlConfig,
    jobExecutionsRolloutConfig: $j.jobExecutionsRolloutConfig,
    abortConfig: $j.abortConfig,
    timeoutConfig: $j.timeoutConfig
  } | with_entries(select(.value != null))')
aws iot create-job --cli-input-json "$input" --query jobId --output text
echo "created fleet job $fleet_job on $fleet_group"

# One release in flight per fleet: cancel the product's older fleet jobs. Their
# queued executions are dropped; a device already updating finishes first.
for id in $(aws iot list-jobs --thing-group-name "$fleet_group" --status IN_PROGRESS \
  --query "jobs[?starts_with(jobId, 'ota-${product}-')].jobId" --output text); do
  [[ "$id" == "$fleet_job" ]] && continue
  targets=$(aws iot describe-job --job-id "$id" --query 'job.targets' --output json)
  if jq -e --arg a "$fleet_arn" 'index($a) != null' <<<"$targets" >/dev/null; then
    aws iot cancel-job --job-id "$id" --reason-code SUPERSEDED --comment "Superseded by $fleet_job" >/dev/null
    echo "cancelled superseded fleet job $id"
  fi
done
