#!/usr/bin/env bash
# Portal users: admin-created only, TOTP required at first sign-in.
#
#   scripts/portal-user.sh add    <username> <email> owner|viewer
#   scripts/portal-user.sh role   <username> owner|viewer|none
#   scripts/portal-user.sh remove <username>      sessions end, user deleted
#   scripts/portal-user.sh list
#
# Cognito emails the temporary password. A lost authenticator or password:
# remove the user and add them again. The first sign-in sets a password
# and enrols an authenticator app. The group is the role: owner, viewer, or
# none (no AWS credentials at all). Users are not in Terraform, so emails
# stay out of its state. Needs the owner's AWS credentials, jq, terraform.
set -euo pipefail

usage() { sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
case "${1:-}" in add | role | remove | list) ;; *) usage ;; esac

root="$(cd "$(dirname "$0")/.." && pwd)"
pool="${PORTAL_USER_POOL:-$(terraform -chdir="$root" output -raw portal_user_pool_id)}"
name_re='^[A-Za-z0-9._-]{2,64}$'

set_role() { # user role
  for g in owner viewer; do
    if [[ "$g" == "$2" ]]; then
      aws cognito-idp admin-add-user-to-group --user-pool-id "$pool" --username "$1" --group-name "$g"
    else
      aws cognito-idp admin-remove-user-from-group --user-pool-id "$pool" --username "$1" --group-name "$g"
    fi
  done
  # Running sessions keep their role until they end: end them.
  aws cognito-idp admin-user-global-sign-out --user-pool-id "$pool" --username "$1"
}

case "${1:-}" in
  add)
    [[ $# -eq 4 && "$2" =~ $name_re && "$3" == *@* && ("$4" == owner || "$4" == viewer) ]] || usage
    aws cognito-idp admin-create-user --user-pool-id "$pool" --username "$2" \
      --user-attributes Name=email,Value="$3" Name=email_verified,Value=true \
      --desired-delivery-mediums EMAIL >/dev/null
    aws cognito-idp admin-add-user-to-group --user-pool-id "$pool" --username "$2" --group-name "$4"
    echo "$2 added as $4; Cognito emailed a temporary password (valid 3 days)."
    ;;
  role)
    [[ $# -eq 3 && "$2" =~ $name_re && ("$3" == owner || "$3" == viewer || "$3" == none) ]] || usage
    set_role "$2" "$3"
    echo "$2 is now $3; their sessions were ended."
    ;;
  remove)
    [[ $# -eq 2 && "$2" =~ $name_re ]] || usage
    aws cognito-idp admin-user-global-sign-out --user-pool-id "$pool" --username "$2"
    aws cognito-idp admin-delete-user --user-pool-id "$pool" --username "$2"
    echo "$2 removed."
    ;;
  list)
    [[ $# -eq 1 ]] || usage
    for g in owner viewer; do
      aws cognito-idp list-users-in-group --user-pool-id "$pool" --group-name "$g" \
        --query 'Users[].[Username,UserStatus]' --output text | sed "s/^/$g\t/"
    done
    ;;
  *) usage ;;
esac
