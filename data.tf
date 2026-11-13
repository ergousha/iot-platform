data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ATS data endpoint the device will connect to (mutual TLS, port 8883).
data "aws_iot_endpoint" "ats" {
  endpoint_type = "iot:Data-ATS"
}

locals {
  # products/<id>.json, one per product (products/README.md). `ergo product
  # init` adds a product with a pull request for its file; no HCL changes.
  product_files = {
    for f in fileset("${path.module}/products", "*.json") :
    trimsuffix(f, ".json") => jsondecode(file("${path.module}/products/${f}"))
  }

  # Every field a product file may set. Keys ending in _reason or _comment
  # are notes; anything else is a typo and fails the plan
  # (terraform_data.products).
  product_fields = [
    "description", "github_repository", "github_repository_id", "soak_hours", "shadow_name",
    "display_name", "fleet_group_name", "canary_group_name",
    "excluded_group_name", "provisioning_template_name", "github_actions_role_name",
  ]

  # The products with every optional field resolved. Everything per-product
  # iterates over this map.
  products = {
    for id, p in local.product_files : id => {
      description          = p.description
      github_repository    = p.github_repository
      github_repository_id = p.github_repository_id
      soak_hours           = try(p.soak_hours, 6)

      fleet_group_name           = coalesce(try(p.fleet_group_name, null), "${var.project_name}-${id}-fleet")
      canary_group_name          = coalesce(try(p.canary_group_name, null), "${var.project_name}-${id}-canary")
      excluded_group_name        = coalesce(try(p.excluded_group_name, null), "${var.project_name}-${id}-excluded")
      provisioning_template_name = coalesce(try(p.provisioning_template_name, null), "${var.project_name}-${id}-fleet-template")
      github_actions_role_name   = coalesce(try(p.github_actions_role_name, null), "${var.project_name}-${id}-github-actions-role")
      shadow_name                = coalesce(try(p.shadow_name, null), id)
      # The repository name without its owner and a trailing -rust.
      display_name = coalesce(try(p.display_name, null), trimsuffix(element(split("/", p.github_repository), 1), "-rust"))
    }
  }

  # The state bucket of versions.tf's backend (backend blocks take no
  # expressions). Products' cloud/ roots keep their state there too.
  state_bucket = "${var.project_name}-tfstate-${data.aws_caller_identity.current.account_id}"

  # The provisioning template ARNs, built as strings rather than read from the
  # template resources. This lets the hook's Lambda permission be created
  # BEFORE the templates (a template refuses a hook it cannot invoke), which
  # breaks the chicken-and-egg loop.
  provisioning_template_arns = {
    for id, p in local.products :
    id => "arn:aws:iot:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:provisioningtemplate/${p.provisioning_template_name}"
  }
}

# The product files' contract, checked at plan time (a typo or a broken id
# fails the plan rather than creating odd resources).
resource "terraform_data" "products" {
  input = keys(local.products)

  lifecycle {
    precondition {
      condition     = length(local.products) > 0
      error_message = "products/ holds no <id>.json."
    }
    precondition {
      condition     = alltrue([for id in keys(local.products) : can(regex("^[a-z][a-z0-9]{1,15}$", id))])
      error_message = "Product ids (the file names in products/) are 2-16 lowercase letters and digits, starting with a letter (they appear in S3 keys, job ids, rule names and resource names)."
    }
    precondition {
      condition = alltrue(flatten([
        for id, p in local.product_files : [
          for k in keys(p) : contains(local.product_fields, k) || endswith(k, "_reason") || endswith(k, "_comment")
        ]
      ]))
      error_message = "A products/<id>.json has a field products/README.md does not list (a typo?)."
    }
    precondition {
      condition = alltrue([
        for p in values(local.products) :
        can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", p.github_repository)) && floor(p.github_repository_id) == p.github_repository_id && p.github_repository_id > 0
      ])
      error_message = "github_repository is owner/name and github_repository_id its positive numeric id."
    }
    precondition {
      condition     = alltrue([for p in values(local.products) : p.soak_hours >= 0 && p.soak_hours <= 168 && floor(p.soak_hours) == p.soak_hours])
      error_message = "soak_hours is a whole number of hours from 0 to 168."
    }
    precondition {
      condition     = alltrue([for p in values(local.products) : can(regex("^[A-Za-z0-9_-]{1,64}$", p.shadow_name)) && p.shadow_name != "platform"])
      error_message = "shadow_name is a shadow name (letters, digits, _ and -) and never `platform`, the shadow only devices write."
    }
    precondition {
      condition     = length(distinct([for p in values(local.products) : p.github_repository])) == length(local.products)
      error_message = "Each product needs its own GitHub repository (the repository is what its CI role trusts)."
    }
  }
}
