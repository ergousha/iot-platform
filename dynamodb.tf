# ---------------------------------------------------------------------------
# Device registry database.
# PAY_PER_REQUEST = on-demand: nothing is billed while idle (no reserved
# capacity), only per request. on_demand_throughput caps it at 2 reads and 2
# writes per second (free to set): even sustained abuse stays near $5 a month.
# The registry sees a few requests a month.
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "device_registry" {
  name         = "${var.project_name}-device-registry"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "mac_address"

  attribute {
    name = "mac_address"
    type = "S"
  }

  on_demand_throughput {
    max_read_request_units  = 2
    max_write_request_units = 2
  }

  # The registry binds devices to their keys: keep 35 days of recovery. Billed
  # by table size, about $0.000001 a month for a few KB.
  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true # AWS-owned KMS key (no additional charge).
  }

  tags = {
    Name = "${var.project_name}-device-registry"
  }
}
