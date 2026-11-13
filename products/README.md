# Products

One file per product on the platform: `<id>.json`, where `<id>` is the
product id (`^[a-z][a-z0-9]{1,15}$`). It is the S3 prefix of its releases,
part of every OTA job id, the `product` of its registry records and things,
and the prefix of its IoT rules (`<id>_*`).

`ergo product init` (iot-device-sdk) writes a new product's file in a pull
request; merging it and running `terraform apply` creates the product's
fleet, canary and excluded groups, provisioning template, GitHub OIDC role
and SSM parameters. Removing a file removes the product (its groups must be
empty).

| Field | Required | Meaning |
|---|---|---|
| `description` | yes | One line, shown on resources and in the portal |
| `github_repository` | yes | `owner/name`; only its Environment `release` may publish this product's firmware |
| `github_repository_id` | yes | The repository's immutable numeric id (`gh api repos/<owner>/<name> --jq .id`) |
| `soak_hours` | no, 6 | Hours a release runs on the canaries before the fleet job (0–168) |
| `shadow_name` | no, the id | The product's named shadow, where the portal owner may set desired state; never `platform` |
| `display_name` | no | The portal name; default the repository name without a trailing `-rust` |
| `*_name` | no | Pinned resource names; only the gateway uses them, so nothing live is renamed |

Keys ending in `_reason` (or `_comment`) are notes for people and ignored.
