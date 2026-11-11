#!/usr/bin/env bash
# One-off cleanup after the Phase 3 apply (platform plan §9): removes every
# copy of the old claim (and the gateway's compiled-in Wi-Fi) that AWS still
# holds.
#
#   scripts/purge-pre-phase3.sh            show what would be deleted
#   scripts/purge-pre-phase3.sh --delete   delete it (asks once more)
#
# 1. The firmware bucket: every object (and object version) outside
#    releases/. Pre-Phase 3 images carry the claim, the gateway's also the
#    Wi-Fi PSK, and they were served only through the now-deleted presign role.
# 2. The Terraform state: every noncurrent version of the state object. Older
#    states hold the claim's private key (aws_iot_certificate.claim and the
#    SSM parameters). It refuses unless the CURRENT state holds no private key,
#    i.e. unless the Phase 3 apply (which drops the claim from the state) ran.
#
# Run it after the controller has rotated the claim (scripts/ota.sh status
# shows nothing; the "claim rotated" email arrived), so the deleted copies
# were already useless. Needs the owner's AWS credentials and jq.
set -euo pipefail

mode="${1:-}"
[[ -z "$mode" || "$mode" == --delete ]] || { echo "usage: $0 [--delete]" >&2; exit 2; }

account=$(aws sts get-caller-identity --query Account --output text)
firmware="${FIRMWARE_BUCKET:-esp32-ztp-firmware-$account}"
state_bucket="${STATE_BUCKET:-esp32-ztp-tfstate-$account}"
state_key="${STATE_KEY:-esp32-ztp/terraform.tfstate}"

# --- the claim must be the controller's --------------------------------------
if aws ssm get-parameter --name /iot-platform/claim/cert --query Parameter.Name --output text >/dev/null 2>&1; then
  echo "claim: rotated by the controller (/iot-platform/claim/cert exists)"
else
  echo "refusing: /iot-platform/claim/cert does not exist yet; the controller has not rotated the claim." >&2
  echo "Wait for the next tick, or run scripts/ota.sh rotate-claim." >&2
  exit 1
fi

# --- 1. firmware bucket -------------------------------------------------------
versioning=$(aws s3api get-bucket-versioning --bucket "$firmware" --query Status --output text)
objects=$(aws s3api list-object-versions --bucket "$firmware" --output json |
  jq -c '[(.Versions // [])[], (.DeleteMarkers // [])[]] | map(select(.Key | startswith("releases/") | not)) | map({Key, VersionId})')
count=$(jq length <<<"$objects")
echo "firmware bucket $firmware (versioning: $versioning): $count object version(s) outside releases/"
jq -r '.[] | "  \(.Key) \(.VersionId)"' <<<"$objects" | head -50
((count <= 50)) || echo "  ... and $((count - 50)) more"

# --- 2. state versions --------------------------------------------------------
current=$(mktemp)
trap 'rm -f "$current"' EXIT
aws s3 cp --quiet "s3://$state_bucket/$state_key" "$current"
if grep -q 'PRIVATE KEY' "$current"; then
  echo "refusing: the current state still holds a private key. Run the Phase 3 terraform apply first." >&2
  exit 1
fi
noncurrent=$(aws s3api list-object-versions --bucket "$state_bucket" --prefix "$state_key" --output json |
  jq -c --arg k "$state_key" '[(.Versions // [])[] | select(.Key == $k and .IsLatest == false) | {Key, VersionId}]')
echo "state $state_bucket/$state_key: current version holds no private key; $(jq length <<<"$noncurrent") noncurrent version(s)"

if [[ "$mode" != --delete ]]; then
  echo "dry run; --delete deletes the above"
  exit 0
fi
read -r -p "Delete them permanently? [y/N] " answer
[[ "$answer" == [yY] ]] || { echo "nothing deleted"; exit 1; }

delete_all() { # bucket, JSON array of {Key, VersionId}
  local bucket="$1" list="$2" n
  n=$(jq length <<<"$list")
  for ((i = 0; i < n; i += 1000)); do
    aws s3api delete-objects --bucket "$bucket" \
      --delete "$(jq -c --argjson i "$i" '{Objects: .[$i:$i+1000], Quiet: true}' <<<"$list")" >/dev/null
  done
  echo "deleted $n object version(s) from $bucket"
}
((count == 0)) || delete_all "$firmware" "$objects"
[[ "$(jq length <<<"$noncurrent")" == 0 ]] || delete_all "$state_bucket" "$noncurrent"
echo "done. The gateway's old PSK is no longer in AWS; per the owner's decision it is not rotated."
