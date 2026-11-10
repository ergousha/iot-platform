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

variable "claim_active" {
  description = "Whether the shared claim certificate is ACTIVE. Keep false: scripts/claim-window.sh opens a timed enrolment window instead."
  type        = bool
  default     = false
}

variable "debug_telemetry_logs" {
  description = "Route device telemetry (dt/+/data, dt/+/opcua) to CloudWatch Logs. Costs per message; enable only while debugging or for a gateway HIL run."
  type        = bool
  default     = false
}

variable "telemetry_topic_prefix" {
  description = "Telemetry topic prefix for devices to publish to."
  type        = string
  default     = "dt"
}

variable "products" {
  description = <<-EOT
    Every device product on the platform, keyed by a short product id. The id
    is the firmware bucket prefix (s3://<bucket>/<id>/firmware_vX.Y.Z.bin), part
    of every OTA job id, and the `product` attribute a registry record and a
    provisioned thing carry.

    Each product gets its own fleet thing group (target of its OTA jobs), canary
    group, provisioning template, SSM template parameter and GitHub Actions
    role, so releases of one product can never reach another.

    The *_name fields default to "<project_name>-<id>-..." names; the gateway
    pins the names it had before products existed, so no live resource is
    renamed (a rename would recreate it).
  EOT
  type = map(object({
    description = string

    # GitHub repository whose main branch may publish this product's firmware.
    github_repository    = string
    github_repository_id = number

    # Things placed in the canary group. A thing can only be in one group of a
    # hierarchy and new devices start in the fleet group, so move a device out
    # of it first (aws iot update-thing-groups-for-thing --thing-name <thing>
    # --thing-groups-to-remove <fleet group>). A thing must exist before it can
    # be listed here.
    canary_things = optional(list(string), [])

    # true: the device keeps its private key in a secure element and enrols with
    # a CSR. The pre-provisioning hook then requires the registry record's
    # public_key to match the key in the new certificate; the shared secret is
    # not accepted for this product.
    require_public_key = optional(bool, false)

    # This product owned the platform before products existed. Firmware at the
    # bucket root (firmware_vX.Y.Z.bin, where its releases used to go) and
    # registry records without a `product` attribute belong to it. At most one
    # product may set it.
    legacy = optional(bool, false)

    fleet_group_name           = optional(string)
    canary_group_name          = optional(string)
    provisioning_template_name = optional(string)
    github_actions_role_name   = optional(string)
  }))

  default = {
    gateway = {
      description          = "OPC UA gateway (Waveshare ESP32-S3-ETH)"
      github_repository    = "ergousha/esp32-opcua-gateway-rust"
      github_repository_id = 1302001123
      canary_things        = ["28848553144F"]
      legacy               = true

      fleet_group_name           = "esp32-ztp-fleet"
      canary_group_name          = "esp32-ztp-canary"
      provisioning_template_name = "esp32-s3-fleet-template"
      github_actions_role_name   = "esp32-ztp-github-actions-role"
    }
    vaktus = {
      description          = "Vaktu's-Salat prayer-times display (ESP32 + ATECC608B)"
      github_repository    = "ergousha/esp32-display-vaktus-salat-rust"
      github_repository_id = 1290322529
      require_public_key   = true
      # The bench unit (ATECC608B 0123C471D3B627CFEE). Before applying, move it
      # out of the fleet group (a thing can be in one group of a hierarchy):
      # aws iot update-thing-groups-for-thing --thing-name 38182B8456F4 \
      #   --thing-groups-to-remove esp32-ztp-vaktus-fleet
      canary_things = ["38182B8456F4"]
    }
  }

  validation {
    condition     = alltrue([for id in keys(var.products) : can(regex("^[a-z][a-z0-9]{1,15}$", id))])
    error_message = "Product ids are 2-16 lowercase letters and digits, starting with a letter (they appear in S3 keys, job ids and resource names)."
  }

  validation {
    condition = alltrue(flatten([
      for p in values(var.products) : [for t in p.canary_things : can(regex("^[a-zA-Z0-9:_-]{1,128}$", t))]
    ]))
    error_message = "Canary thing names are 1-128 characters of letters, digits, ':', '_' and '-'."
  }

  validation {
    condition     = length([for p in values(var.products) : p if p.legacy]) <= 1
    error_message = "At most one product may set legacy."
  }

  validation {
    condition     = length(distinct([for p in values(var.products) : p.github_repository])) == length(var.products)
    error_message = "Each product needs its own GitHub repository (the repository is what its CI role trusts)."
  }
}

variable "github_owner_id" {
  description = "Permanent numeric ID of the GitHub repository owner."
  type        = number
  default     = 2912014
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
  description = "The abort percentage is only applied once this many devices have been notified of the job. 1: with a handful of devices, the first failure on a canary stops the release."
  type        = number
  default     = 1

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
