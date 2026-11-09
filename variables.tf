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

variable "provisioning_template_name" {
  description = "Fleet Provisioning template name. Must match the firmware."
  type        = string
  default     = "esp32-s3-fleet-template"
}

variable "log_retention_days" {
  description = "CloudWatch log retention period (kept low for cost reasons)."
  type        = number
  default     = 7
}

variable "telemetry_topic_prefix" {
  description = "Telemetry topic prefix for devices to publish to."
  type        = string
  default     = "dt"
}

variable "github_repositories" {
  description = "Allowed GitHub repositories with their numeric IDs"
  type = list(object({
    name          = string
    repository_id = number
  }))
  default = [
    {
      name          = "ergousha/esp32-opcua-gateway-rust"
      repository_id = 1302001123
    },
    {
      name          = "ergousha/esp32-display-vaktus-salat-rust"
      repository_id = 1290322529
    }
  ]
}

variable "github_owner_id" {
  description = "Permanent numeric ID of the GitHub repository owner."
  type        = number
  default     = 2912014
}

variable "ota_canary_things" {
  description = "Things placed in the canary thing group. AWS IoT allows a thing in only one group of a hierarchy, and devices provisioned after the fleet group existed start in it, so move such a device out of the fleet group before listing it here (aws iot update-thing-groups-for-thing --thing-name <thing> --thing-groups-to-remove <fleet group>)."
  type        = list(string)
  default     = ["28848553144F"]

  validation {
    condition     = alltrue([for t in var.ota_canary_things : can(regex("^[a-zA-Z0-9:_-]{1,128}$", t))])
    error_message = "Thing names are 1-128 characters of letters, digits, ':', '_' and '-'."
  }
}

# ---------------------------------------------------------------------------
# OTA job rollout policy. The ota_trigger Lambda receives these as environment
# variables and re-checks the same ranges (the ones AWS IoT accepts) at start.
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

variable "ota_abort_failure_percentage" {
  description = "Cancel an OTA job once at least this percentage of its executions ended FAILED, TIMED_OUT or REJECTED."
  type        = number
  default     = 20

  validation {
    condition     = can(regex("^[0-9]+([.][0-9]{1,2})?$", tostring(var.ota_abort_failure_percentage))) && var.ota_abort_failure_percentage >= 0.01 && var.ota_abort_failure_percentage <= 100
    error_message = "Must be from 0.01 to 100 with at most two decimal places."
  }
}

variable "ota_abort_min_executed_things" {
  description = "The abort percentage is only applied once this many devices have been notified of the job, so the first few results cannot cancel a release on their own."
  type        = number
  default     = 10

  validation {
    condition     = floor(var.ota_abort_min_executed_things) == var.ota_abort_min_executed_things && var.ota_abort_min_executed_things >= 1
    error_message = "Must be an integer of at least 1."
  }
}

variable "ota_in_progress_timeout_minutes" {
  description = "Minutes a job execution may stay IN_PROGRESS before AWS IoT marks it TIMED_OUT (a device that died or never came back)."
  type        = number
  default     = 30

  validation {
    condition     = floor(var.ota_in_progress_timeout_minutes) == var.ota_in_progress_timeout_minutes && var.ota_in_progress_timeout_minutes >= 1 && var.ota_in_progress_timeout_minutes <= 10080
    error_message = "Must be an integer from 1 to 10080 (7 days)."
  }
}
