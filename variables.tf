variable "aws_region" {
  description = "AWS region (choose a region supported by IoT Core)."
  type        = string
  default     = "eu-central-1"
}

variable "project_name" {
  description = "Prefix for resource naming."
  type        = string
  default     = "esp32-ztp"
}

variable "log_retention_days" {
  description = "CloudWatch log retention period (kept low for cost reasons)."
  type        = number
  default     = 3
}

variable "telemetry_topic_prefix" {
  description = "Telemetry topic prefix for devices to publish to."
  type        = string
  default     = "dt"
}

variable "github_owner_id" {
  description = "Permanent numeric ID of the GitHub repository owner."
  type        = number
  default     = 2912014
}

# ---------------------------------------------------------------------------
# OTA jobs. The ota_controller Lambda receives these as environment variables
# and re-checks the same ranges (the ones AWS IoT accepts) at start. Failures
# are the controller's to judge (halt, exclusion, rerun), so jobs carry no
# abort configuration.
# ---------------------------------------------------------------------------
variable "ota_rollout_base_rate_per_minute" {
  description = "Devices notified per minute when an OTA job starts (exponential rollout base rate)."
  type        = number
  default     = 1

  validation {
    condition     = floor(var.ota_rollout_base_rate_per_minute) == var.ota_rollout_base_rate_per_minute && var.ota_rollout_base_rate_per_minute >= 1 && var.ota_rollout_base_rate_per_minute <= 1000
    error_message = "Must be an integer from 1 to 1000."
  }
}

variable "ota_rollout_increment_factor" {
  description = "Factor the rollout rate is multiplied by at each step."
  type        = number
  default     = 2

  validation {
    condition     = can(regex("^[0-9]+([.][0-9])?$", tostring(var.ota_rollout_increment_factor))) && var.ota_rollout_increment_factor >= 1.1 && var.ota_rollout_increment_factor <= 5
    error_message = "Must be from 1.1 to 5 with at most one decimal place."
  }
}

variable "ota_rollout_succeeded_things" {
  description = "The rollout rate steps up each time this many more devices have reported SUCCEEDED."
  type        = number
  default     = 5

  validation {
    condition     = floor(var.ota_rollout_succeeded_things) == var.ota_rollout_succeeded_things && var.ota_rollout_succeeded_things >= 1
    error_message = "Must be an integer of at least 1."
  }
}

variable "ota_rollout_max_per_minute" {
  description = "Upper bound on devices notified per minute. Must not be below the base rate."
  type        = number
  default     = 20

  validation {
    condition     = floor(var.ota_rollout_max_per_minute) == var.ota_rollout_max_per_minute && var.ota_rollout_max_per_minute >= 1
    error_message = "Must be an integer of at least 1."
  }
}

variable "ota_in_progress_timeout_minutes" {
  description = "Minutes a job execution may stay IN_PROGRESS before AWS IoT marks it TIMED_OUT (a device that died or never came back). Two retries follow."
  type        = number
  default     = 60

  validation {
    condition     = floor(var.ota_in_progress_timeout_minutes) == var.ota_in_progress_timeout_minutes && var.ota_in_progress_timeout_minutes >= 1 && var.ota_in_progress_timeout_minutes <= 10080
    error_message = "Must be an integer from 1 to 10080 (7 days)."
  }
}

variable "firmware_download_url_template" {
  description = <<-EOT
    Image URL put into OTA job documents, with {product}, {version} and
    {repository} placeholders. Empty: the firmware CloudFront distribution,
    https://<distribution>/{product}/{version}/app.bin. The fallback if the
    distribution cannot be on the CloudFront Free plan:
    https://github.com/{repository}/releases/download/v{version}/app.bin
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.firmware_download_url_template == "" || (startswith(var.firmware_download_url_template, "https://") && strcontains(var.firmware_download_url_template, "{version}"))
    error_message = "Must be empty or an https URL with a {version} placeholder."
  }
}

variable "release_workflow" {
  description = "The reusable workflow (owner/repo/path, no ref) every product's release must run in to assume its GitHub OIDC role (the job_workflow_ref claim)."
  type        = string
  default     = "ergousha/iot-device-sdk/.github/workflows/firmware-release.yml"
}

# ---------------------------------------------------------------------------
# Guard rails (guard.tf). Thresholds sit 20x or more above the measured
# baseline: at most 48 publishes and 4 connects per 5 minutes (Nov 2026).
# ---------------------------------------------------------------------------
variable "alert_email" {
  description = "Email for guard alarms, kill-switch trips and budget warnings. Required: the kill switch can take the fleet offline and must never do so silently. Set it in terraform.tfvars (gitignored); AWS sends a confirmation mail whose link must be clicked."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "Must be an email address."
  }
}

variable "guard_publish_per_5min" {
  description = "Fleet-wide IoT publishes per 5 minutes above which the traffic scope trips; 6 periods in a row trip the fleet scope. It counts messages, not bytes: 1,000 small messages per 5 min is about $10 a month if sustained, but AWS bills per 5 KB, so a flood of large messages just under the threshold is only stopped by the budgets."
  type        = number
  default     = 1000
}

variable "guard_connect_per_5min" {
  description = "Fleet-wide IoT connects per 5 minutes above which the provisioning scope trips."
  type        = number
  default     = 30
}

variable "guard_hook_per_5min" {
  description = "Pre-provisioning hook invocations per 5 minutes above which the provisioning scope trips."
  type        = number
  default     = 10
}

variable "guard_budget_traffic_usd" {
  description = "Monthly cost (USD) at which the traffic scope trips. Email warnings at 50 % actual and 100 % forecast."
  type        = number
  default     = 10
}

variable "guard_budget_fleet_usd" {
  description = "Monthly cost (USD) at which the fleet scope trips: every device is cut off."
  type        = number
  default     = 25

  validation {
    condition     = var.guard_budget_fleet_usd > var.guard_budget_traffic_usd
    error_message = "Must be above guard_budget_traffic_usd: the fleet scope is the last resort."
  }
}

# ---------------------------------------------------------------------------
# Portal (portal.tf).
# ---------------------------------------------------------------------------
variable "portal_domain_prefix" {
  description = "Cognito hosted-UI domain prefix (https://<prefix>.auth.<region>.amazoncognito.com). Empty: <project_name>-portal-<account id>."
  type        = string
  default     = ""

  validation {
    condition     = var.portal_domain_prefix == "" || can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", var.portal_domain_prefix))
    error_message = "Lower-case letters, digits and hyphens, at most 63 characters."
  }
}
