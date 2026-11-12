#!/usr/bin/env bash
# Builds the portal SPA and uploads it to its bucket.
#
#   scripts/portal-deploy.sh
#
# Run after `terraform apply` (which writes config.json into the bucket) and
# after any change under portal/. The build installs exactly the committed
# lockfile with no install scripts. Hashed assets are cached for a year at
# the edge, index.html for a minute, so no CloudFront invalidation is needed
# (and none is billed). Needs the owner's AWS credentials, npm, terraform.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
bucket="${PORTAL_BUCKET:-$(terraform -chdir="$root" output -raw portal_bucket_name)}"
url="$(terraform -chdir="$root" output -raw portal_url 2>/dev/null || true)"

cd "$root/portal"
npm ci --ignore-scripts
npm test
npm run build

# Nothing but the build may go out: refuse anything that looks like a secret.
if grep -rIl -e 'PRIVATE KEY' -e 'aws_secret_access_key' -e 'AKIA[0-9A-Z]\{16\}' dist; then
  echo "refusing: the build contains something that looks like a secret" >&2
  exit 1
fi

# Assets first, so a new index.html never points at a missing file. Old
# assets stay until the next deploy (a page loaded before it still works).
aws s3 sync dist/assets "s3://$bucket/assets" --cache-control "public, max-age=31536000, immutable"
aws s3 cp dist/index.html "s3://$bucket/index.html" --cache-control "max-age=60" --content-type "text/html; charset=utf-8"
aws s3 sync dist "s3://$bucket" --delete --exclude config.json --exclude index.html --exclude 'assets/*' \
  --cache-control "max-age=60"
echo "deployed to s3://$bucket ${url:+($url)}"
