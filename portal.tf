# ===========================================================================
# Platform portal.
#
# A static SPA (portal/) on its own CloudFront origin. Sign-in is Cognito
# managed login (Essentials tier, TOTP required, admin-created users only),
# styled like the portal; an identity
# pool turns the ID token into short-lived credentials of one of two roles,
# chosen by the user's Cognito group:
#
#   owner   reads everything, sets desired state on product shadows, moves
#           devices between their product's fleet, canary and excluded
#           groups, reads CloudTrail, and sends every other change through
#           the OTA controller's AWS_IAM Function URL;
#   viewer  reads (family, installer); the controller answers its Function
#           URL calls with status only.
#
# No browser role can touch certificates, the claim, templates, the registry
# or jobs. A user in neither group gets no credentials at all (ambiguous role
# resolution: Deny). The Cognito user name is a session tag, so CloudTrail
# ties each session to a person.
#
# Cost: $0. Cognito Essentials (10,000 monthly active users free, with no
# end date) and identity pools are free at this size,
# CloudFront is on the Free flat-rate plan (attach it in the console after the
# first apply, as for the firmware distribution in cloudfront.tf) which
# includes the headers function, and the bucket holds a few hundred KB.
#
# Users are not in Terraform (their emails would be in state):
# scripts/portal-user.sh adds them. The SPA is not either:
# scripts/portal-deploy.sh builds and uploads it; Terraform writes only its
# config.json.
# ===========================================================================

locals {
  portal_prefix = "${var.project_name}-portal"

  # Cognito prefix domains are global per region; the account id makes it ours.
  portal_domain_prefix = coalesce(var.portal_domain_prefix, "${local.portal_prefix}-${data.aws_caller_identity.current.account_id}")
  portal_auth_origin   = "https://${local.portal_domain_prefix}.auth.${data.aws_region.current.region}.amazoncognito.com"
  portal_origin        = "https://${aws_cloudfront_distribution.portal.domain_name}"

  # Role names as strings: the controller's environment names the viewer role
  # without depending on it.
  portal_owner_role_name  = "${local.portal_prefix}-owner"
  portal_viewer_role_name = "${local.portal_prefix}-viewer"

  region = data.aws_region.current.region

  # Every origin the SPA talks to. The Function URL is a wildcard: its exact
  # host would make a cycle (its CORS names the portal origin).
  portal_connect_src = [
    "'self'",
    local.portal_auth_origin,
    "https://cognito-identity.${local.region}.amazonaws.com",
    "https://iot.${local.region}.amazonaws.com",
    "https://${data.aws_iot_endpoint.ats.endpoint_address}",
    "https://dynamodb.${local.region}.amazonaws.com",
    "https://ssm.${local.region}.amazonaws.com",
    "https://monitoring.${local.region}.amazonaws.com",
    "https://cloudtrail.${local.region}.amazonaws.com",
    "https://*.lambda-url.${local.region}.on.aws",
  ]

  portal_csp = join("; ", [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src ${join(" ", local.portal_connect_src)}",
    "frame-ancestors 'none'",
    "frame-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "object-src 'none'",
  ])

  # The registry attributes the portal may read: everything but `secret`.
  portal_registry_attributes = [
    "mac_address", "product", "allowed", "provisioned", "enrol_by", "canary", "public_key",
    "last_provisioned_serial", "last_certificate_id", "last_provisioned_via", "last_provisioned_at",
  ]
}

# ---------------------------------------------------------------------------
# Hosting: a private bucket behind its own CloudFront distribution (OAC).
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "portal" {
  bucket = "${local.portal_prefix}-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "portal" {
  bucket                  = aws_s3_bucket.portal.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "portal" {
  bucket = aws_s3_bucket.portal.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "portal" {
  bucket = aws_s3_bucket.portal.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_cloudfront_origin_access_control" "portal" {
  name                              = local.portal_prefix
  description                       = "Portal SPA in ${aws_s3_bucket.portal.id}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# The browser hardening: tokens never leave this origin, the page cannot be
# framed, and no device-written text can run as script. Set by a viewer-
# response CloudFront Function, not a response headers policy: the Free
# flat-rate plan allows only AWS-managed headers policies, and none of those
# carries a CSP. The function must serve this distribution only (a plan
# refuses shared functions). CloudFront runs it for responses under 400, so
# S3's error documents go without these headers; they hold no script.
locals {
  portal_headers = {
    "content-security-policy"    = local.portal_csp
    "x-frame-options"            = "DENY"
    "strict-transport-security"  = "max-age=63072000; includeSubDomains"
    "x-content-type-options"     = "nosniff"
    "referrer-policy"            = "no-referrer"
    "permissions-policy"         = "camera=(), microphone=(), geolocation=(), usb=(), serial=(), bluetooth=(), hid=(), payment=(), clipboard-read=()"
    "cross-origin-opener-policy" = "same-origin"
  }
}

resource "aws_cloudfront_function" "portal_headers" {
  name    = "${local.portal_prefix}-headers"
  comment = "Portal security headers"
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = <<-EOT
    var HEADERS = ${jsonencode(local.portal_headers)};

    function handler(event) {
      var headers = event.response.headers;
      for (var name in HEADERS) {
        headers[name] = { value: HEADERS[name] };
      }
      return event.response;
    }
  EOT
}

resource "aws_cloudfront_distribution" "portal" {
  enabled             = true
  comment             = "${var.project_name} portal"
  is_ipv6_enabled     = true
  http_version        = "http2"
  price_class         = "PriceClass_100"
  default_root_object = "index.html"

  origin {
    origin_id                = "portal"
    domain_name              = aws_s3_bucket.portal.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.portal.id
  }

  # Cached at the edge by the objects' own Cache-Control (scripts/
  # portal-deploy.sh): hashed assets for a year, index.html and config.json
  # for a minute. No invalidations needed.
  default_cache_behavior {
    target_origin_id       = "portal"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    viewer_protocol_policy = "redirect-to-https"
    cache_policy_id        = data.aws_cloudfront_cache_policy.caching_optimized.id
    compress               = true

    function_association {
      event_type   = "viewer-response"
      function_arn = aws_cloudfront_function.portal_headers.arn
    }
  }

  # Missing paths are cached too, so probing random URLs barely reaches S3.
  dynamic "custom_error_response" {
    for_each = toset([403, 404])
    content {
      error_code            = custom_error_response.value
      error_caching_min_ttl = 300
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  lifecycle {
    # The Free plan's own WAF web ACL and price class (see cloudfront.tf).
    ignore_changes = [web_acl_id, price_class]
  }
}

data "aws_iam_policy_document" "portal_bucket" {
  statement {
    sid       = "CloudFrontReadsPortal"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.portal.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.portal.arn]
    }
  }

  statement {
    sid     = "TLSOnly"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.portal.arn,
      "${aws_s3_bucket.portal.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "portal" {
  bucket     = aws_s3_bucket.portal.id
  policy     = data.aws_iam_policy_document.portal_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.portal]
}

# ---------------------------------------------------------------------------
# Cognito: who may sign in.
# ---------------------------------------------------------------------------
resource "aws_cognito_user_pool" "portal" {
  name = local.portal_prefix
  # Essentials, not Lite: managed login and its branding (below) need it.
  # Both have the same free 10,000 monthly active users.
  user_pool_tier      = "ESSENTIALS"
  deletion_protection = "ACTIVE"

  # TOTP for everyone, no SMS (it bills, and SIM swaps).
  mfa_configuration = "ON"
  software_token_mfa_configuration {
    enabled = true
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  # No self-service recovery: the owner resets a user (portal-user.sh).
  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = false
    temporary_password_validity_days = 3
  }

  username_configuration {
    case_sensitive = false
  }
}

resource "aws_cognito_user_pool_domain" "portal" {
  domain                = local.portal_domain_prefix
  user_pool_id          = aws_cognito_user_pool.portal.id
  managed_login_version = 2 # managed login, with the branding below
}

# A public client: authorization code with PKCE, no secret. Tokens stay in
# the SPA's memory; a reload signs in again through managed login's session
# cookie.
resource "aws_cognito_user_pool_client" "portal" {
  name         = local.portal_prefix
  user_pool_id = aws_cognito_user_pool.portal.id

  generate_secret                      = false
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = ["${local.portal_origin}/"]
  logout_urls                          = ["${local.portal_origin}/"]
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]

  enable_token_revocation       = true
  prevent_user_existence_errors = "ENABLED"

  access_token_validity  = 60
  id_token_validity      = 60
  refresh_token_validity = 12
  auth_session_validity  = 3
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "hours"
  }
}

# ---------------------------------------------------------------------------
# The sign-in pages, styled like the portal (portal/src/style.css): the same
# colours in light and dark mode (following the browser), the same radii, and
# the portal's header with its logo. Colours are RRGGBBAA hex. The logos come
# from portal/branding/logo.html (scripts/portal-branding.sh).
# ---------------------------------------------------------------------------
locals {
  portal_brand = {
    lightMode = {
      page        = "f4f6f9ff"
      surface     = "ffffffff"
      text        = "18202bff"
      muted       = "5e6b7bff"
      faint       = "8a95a3ff"
      line        = "e2e7eeff"
      field       = "c9d1dbff"
      hover       = "f1f4f8ff"
      accent      = "2459d6ff"
      accent_down = "1b46adff"
      accent_soft = "e7eefdff"
      on_accent   = "ffffffff"
      ok          = "18794eff"
      ok_soft     = "e3f4eaff"
      warn        = "8a5a00ff"
      warn_soft   = "fff1d1ff"
      danger      = "c0352bff"
      danger_soft = "fdecebff"
    }
    darkMode = {
      page        = "0f1318ff"
      surface     = "171c23ff"
      text        = "e6eaefff"
      muted       = "9aa6b4ff"
      faint       = "6f7b89ff"
      line        = "29313bff"
      field       = "3a4450ff"
      hover       = "1e252eff"
      accent      = "7ea6ffff"
      accent_down = "a3bfffff"
      accent_soft = "1c2a47ff"
      on_accent   = "10151bff"
      ok          = "5fd39aff"
      ok_soft     = "133224ff"
      warn        = "f2c063ff"
      warn_soft   = "3a2f12ff"
      danger      = "ff8b80ff"
      danger_soft = "3d1d1bff"
    }
  }

  portal_branding_settings = {
    categories = {
      auth = {
        authMethodOrder = [[
          { display = "BUTTON", type = "FEDERATED" },
          { display = "INPUT", type = "USERNAME_PASSWORD" },
        ]]
        federation = { interfaceStyle = "BUTTON_LIST", order = [] }
      }
      form = {
        displayGraphics     = true
        instructions        = { enabled = false }
        languageSelector    = { enabled = false }
        location            = { horizontal = "CENTER", vertical = "CENTER" }
        sessionTimerDisplay = "NONE"
      }
      global = {
        colorSchemeMode = "DYNAMIC" # light or dark, as the browser prefers
        spacingDensity  = "REGULAR"
        pageHeader      = { enabled = true }
        pageFooter      = { enabled = false }
      }
    }

    componentClasses = {
      buttons = { borderRadius = 7.0 }
      divider = { for m, c in local.portal_brand : m => { borderColor = c.line } }
      dropDown = merge({ borderRadius = 7.0 }, { for m, c in local.portal_brand : m => {
        defaults = { itemBackgroundColor = c.surface }
        hover    = { itemBackgroundColor = c.hover, itemBorderColor = c.line, itemTextColor = c.text }
        match    = { itemBackgroundColor = c.accent_soft, itemTextColor = c.accent }
      } })
      focusState = { for m, c in local.portal_brand : m => { borderColor = c.accent } }
      idpButtons = { icons = { enabled = true } }
      input = merge({ borderRadius = 7.0 }, { for m, c in local.portal_brand : m => {
        defaults         = { backgroundColor = c.surface, borderColor = c.field }
        placeholderColor = c.faint
      } })
      inputDescription = { for m, c in local.portal_brand : m => { textColor = c.muted } }
      inputLabel       = { for m, c in local.portal_brand : m => { textColor = c.text } }
      link = { for m, c in local.portal_brand : m => {
        defaults = { textColor = c.accent }
        hover    = { textColor = c.accent_down }
      } }
      optionControls = { for m, c in local.portal_brand : m => {
        defaults = { backgroundColor = c.surface, borderColor = c.field }
        selected = { backgroundColor = c.accent, foregroundColor = c.on_accent }
      } }
      statusIndicator = { for m, c in local.portal_brand : m => {
        error   = { backgroundColor = c.danger_soft, borderColor = c.danger, indicatorColor = c.danger }
        success = { backgroundColor = c.ok_soft, borderColor = c.ok, indicatorColor = c.ok }
        warning = { backgroundColor = c.warn_soft, borderColor = c.warn, indicatorColor = c.warn }
        pending = { indicatorColor = c.muted }
      } }
    }

    components = {
      alert = merge({ borderRadius = 8.0 }, { for m, c in local.portal_brand : m => {
        error = { backgroundColor = c.danger_soft, borderColor = c.danger }
      } })
      favicon = { enabledTypes = ["ICO"] }
      form = merge({
        backgroundImage = { enabled = false }
        borderRadius    = 10.0
        logo            = { enabled = false, formInclusion = "IN", location = "CENTER", position = "TOP" }
      }, { for m, c in local.portal_brand : m => { backgroundColor = c.surface, borderColor = c.line } })
      pageBackground = merge({ image = { enabled = false } }, { for m, c in local.portal_brand : m => { color = c.page } })
      pageFooter = merge({
        backgroundImage = { enabled = false }
        logo            = { enabled = false, location = "START" }
      }, { for m, c in local.portal_brand : m => { background = { color = c.surface }, borderColor = c.line } })
      pageHeader = merge({
        backgroundImage = { enabled = false }
        logo            = { enabled = true, location = "START" }
      }, { for m, c in local.portal_brand : m => { background = { color = c.surface }, borderColor = c.line } })
      pageText = { for m, c in local.portal_brand : m => {
        bodyColor = c.text, descriptionColor = c.muted, headingColor = c.text
      } }
      phoneNumberSelector = { displayType = "TEXT" }
      primaryButton = { for m, c in local.portal_brand : m => {
        defaults = { backgroundColor = c.accent, textColor = c.on_accent }
        hover    = { backgroundColor = c.accent_down, textColor = c.on_accent }
        active   = { backgroundColor = c.accent_down, textColor = c.on_accent }
        disabled = { backgroundColor = c.hover, borderColor = c.line }
      } }
      secondaryButton = { for m, c in local.portal_brand : m => {
        defaults = { backgroundColor = c.surface, borderColor = c.field, textColor = c.text }
        hover    = { backgroundColor = c.hover, borderColor = c.field, textColor = c.text }
        active   = { backgroundColor = c.accent_soft, borderColor = c.accent, textColor = c.accent }
      } }
    }
  }
}

resource "aws_cognito_managed_login_branding" "portal" {
  user_pool_id = aws_cognito_user_pool.portal.id
  client_id    = aws_cognito_user_pool_client.portal.id
  settings     = jsonencode(local.portal_branding_settings)

  asset {
    category   = "PAGE_HEADER_LOGO"
    color_mode = "LIGHT"
    extension  = "PNG"
    bytes      = filebase64("${path.module}/portal/branding/header-logo-light.png")
  }
  asset {
    category   = "PAGE_HEADER_LOGO"
    color_mode = "DARK"
    extension  = "PNG"
    bytes      = filebase64("${path.module}/portal/branding/header-logo-dark.png")
  }
  asset {
    category   = "FAVICON_ICO"
    color_mode = "DYNAMIC"
    extension  = "ICO"
    bytes      = filebase64("${path.module}/portal/public/favicon.ico")
  }

  # Managed login exists only once the domain serves version 2.
  depends_on = [aws_cognito_user_pool_domain.portal]
}

# The group decides the role: the ID token carries cognito:preferred_role.
resource "aws_cognito_user_group" "portal" {
  for_each = {
    owner  = { precedence = 0, role = aws_iam_role.portal_owner.arn, description = "Reads everything; overrides through the OTA controller." }
    viewer = { precedence = 10, role = aws_iam_role.portal_viewer.arn, description = "Read-only." }
  }

  name         = each.key
  user_pool_id = aws_cognito_user_pool.portal.id
  precedence   = each.value.precedence
  role_arn     = each.value.role
  description  = each.value.description
}

# ---------------------------------------------------------------------------
# Identity pool: ID token -> AWS credentials of the group's role.
# ---------------------------------------------------------------------------
resource "aws_cognito_identity_pool" "portal" {
  identity_pool_name               = replace(local.portal_prefix, "-", "_")
  allow_unauthenticated_identities = false
  allow_classic_flow               = false

  cognito_identity_providers {
    client_id               = aws_cognito_user_pool_client.portal.id
    provider_name           = aws_cognito_user_pool.portal.endpoint
    server_side_token_check = true # a revoked or signed-out token gets nothing
  }
}

resource "aws_cognito_identity_pool_roles_attachment" "portal" {
  identity_pool_id = aws_cognito_identity_pool.portal.id

  # Required by the API; unused, since the token rule below resolves every
  # user and Deny answers the rest.
  roles = {
    authenticated = aws_iam_role.portal_viewer.arn
  }

  role_mapping {
    identity_provider         = "${aws_cognito_user_pool.portal.endpoint}:${aws_cognito_user_pool_client.portal.id}"
    type                      = "Token"
    ambiguous_role_resolution = "Deny"
  }
}

# The Cognito user name becomes the session tag `username`: CloudTrail
# records it on each session's AssumeRoleWithWebIdentity.
resource "aws_cognito_identity_pool_provider_principal_tag" "portal" {
  identity_pool_id       = aws_cognito_identity_pool.portal.id
  identity_provider_name = aws_cognito_user_pool.portal.endpoint
  use_defaults           = false
  principal_tags = {
    username = "cognito:username"
  }
}

# ---------------------------------------------------------------------------
# Roles.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "portal_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"]
    principals {
      type        = "Federated"
      identifiers = ["cognito-identity.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "cognito-identity.amazonaws.com:aud"
      values   = [aws_cognito_identity_pool.portal.id]
    }
    condition {
      test     = "ForAnyValue:StringLike"
      variable = "cognito-identity.amazonaws.com:amr"
      values   = ["authenticated"]
    }
  }
}

resource "aws_iam_role" "portal_owner" {
  name                 = local.portal_owner_role_name
  assume_role_policy   = data.aws_iam_policy_document.portal_assume.json
  max_session_duration = 3600
}

resource "aws_iam_role" "portal_viewer" {
  name                 = local.portal_viewer_role_name
  assume_role_policy   = data.aws_iam_policy_document.portal_assume.json
  max_session_duration = 3600
}

# What both roles read.
data "aws_iam_policy_document" "portal_read" {
  statement {
    sid = "IoTRead"
    actions = [
      "iot:DescribeThing", "iot:ListThingGroupsForThing", "iot:ListThingPrincipals",
      "iot:DescribeThingGroup", "iot:ListThingsInThingGroup",
      "iot:DescribeJob", "iot:ListJobExecutionsForJob", "iot:ListJobExecutionsForThing", "iot:DescribeJobExecution",
      "iot:GetThingShadow", "iot:ListNamedShadowsForThing",
    ]
    resources = [
      "${local.iot_arn}:thing/*",
      "${local.iot_arn}:thinggroup/*",
      "${local.iot_arn}:job/*",
    ]
  }

  statement {
    sid       = "IoTListJobs"
    actions   = ["iot:ListJobs"]
    resources = ["*"]
  }

  statement {
    sid       = "Presence"
    actions   = ["dynamodb:Scan"]
    resources = [aws_dynamodb_table.presence.arn]
  }

  # The registry, without the gateway's shared secret: only scans that
  # project the listed attributes are allowed.
  statement {
    sid       = "Registry"
    actions   = ["dynamodb:Scan"]
    resources = [aws_dynamodb_table.device_registry.arn]
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "dynamodb:Attributes"
      values   = local.portal_registry_attributes
    }
    condition {
      test     = "StringEquals"
      variable = "dynamodb:Select"
      values   = ["SPECIFIC_ATTRIBUTES"]
    }
  }

  # Never the claim's cert or key.
  statement {
    sid     = "Parameters"
    actions = ["ssm:GetParameter"]
    resources = [
      aws_ssm_parameter.guard_state.arn,
      "arn:aws:ssm:${local.region}:${data.aws_caller_identity.current.account_id}:parameter${local.claim_parameter_prefix}/state",
      "arn:aws:ssm:${local.region}:${data.aws_caller_identity.current.account_id}:parameter/iot-platform/products/*/signing_keys",
    ]
  }

  statement {
    # DescribeAlarms is authorised against alarm:* whatever the name prefix,
    # so it cannot be narrowed to the guard's alarms. It reads alarm
    # configuration and state only; the SPA asks for the guard prefix.
    sid       = "GuardAlarms"
    actions   = ["cloudwatch:DescribeAlarms"]
    resources = ["*"]
  }

  # The controller's Function URL. The viewer gets status only (the
  # controller checks the caller's role). InvokeFunction is needed alongside
  # InvokeFunctionUrl, but only through the URL: a direct invoke would skip
  # that check.
  statement {
    sid       = "ControllerURL"
    actions   = ["lambda:InvokeFunctionUrl"]
    resources = [aws_lambda_function.ota_controller.arn]
    condition {
      test     = "StringEquals"
      variable = "lambda:FunctionUrlAuthType"
      values   = ["AWS_IAM"]
    }
  }

  statement {
    sid       = "ControllerViaURLOnly"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.ota_controller.arn]
    condition {
      test     = "Bool"
      variable = "lambda:InvokedViaFunctionUrl"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role_policy" "portal_viewer" {
  name   = "${local.portal_viewer_role_name}-policy"
  role   = aws_iam_role.portal_viewer.id
  policy = data.aws_iam_policy_document.portal_read.json
}

data "aws_iam_policy_document" "portal_owner" {
  source_policy_documents = [data.aws_iam_policy_document.portal_read.json]

  statement {
    sid       = "Audit"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }

  # Desired state on each product's own named shadow; never the `platform`
  # shadow, which only devices report.
  statement {
    sid       = "ProductShadows"
    actions   = ["iot:UpdateThingShadow"]
    resources = [for p in local.products : "${local.iot_arn}:thing/*/${p.shadow_name}"]
  }

  # Canary and excluded toggles. Quarantine goes through the controller.
  statement {
    sid     = "Membership"
    actions = ["iot:UpdateThingGroupsForThing"]
    resources = concat(
      local.product_group_arns,
      ["${local.iot_arn}:thing/*"],
    )
  }
}

resource "aws_iam_role_policy" "portal_owner" {
  name   = "${local.portal_owner_role_name}-policy"
  role   = aws_iam_role.portal_owner.id
  policy = data.aws_iam_policy_document.portal_owner.json
}

# ---------------------------------------------------------------------------
# The SPA's configuration: public facts only.
# ---------------------------------------------------------------------------
resource "aws_s3_object" "portal_config" {
  bucket        = aws_s3_bucket.portal.id
  key           = "config.json"
  content_type  = "application/json"
  cache_control = "max-age=60"
  content = jsonencode({
    region           = local.region
    userPoolId       = aws_cognito_user_pool.portal.id
    userPoolEndpoint = aws_cognito_user_pool.portal.endpoint
    clientId         = aws_cognito_user_pool_client.portal.id
    authOrigin       = local.portal_auth_origin
    identityPoolId   = aws_cognito_identity_pool.portal.id
    controllerUrl    = aws_lambda_function_url.ota_controller.function_url
    iotDataEndpoint  = data.aws_iot_endpoint.ats.endpoint_address
    registryTable    = aws_dynamodb_table.device_registry.name
    registryFields   = local.portal_registry_attributes
    presenceTable    = aws_dynamodb_table.presence.name
    guardParameter   = aws_ssm_parameter.guard_state.name
    claimParameter   = "${local.claim_parameter_prefix}/state"
    alarmPrefix      = "${local.guard_prefix}-"
    quarantineGroup  = aws_iot_thing_group.quarantine.name
    products = [for id, p in local.products : {
      id          = id
      fleet       = aws_iot_thing_group.fleet[id].name
      canary      = aws_iot_thing_group.canary[id].name
      excluded    = aws_iot_thing_group.excluded[id].name
      name        = p.display_name
      description = p.description
      shadow      = p.shadow_name
      legacy      = p.legacy
    }]
  })

  depends_on = [aws_s3_bucket_policy.portal]
}

output "portal_url" {
  description = "The portal. Sign in with a user from scripts/portal-user.sh."
  value       = "${local.portal_origin}/"
}

output "portal_bucket_name" {
  description = "Bucket scripts/portal-deploy.sh uploads the SPA to."
  value       = aws_s3_bucket.portal.id
}

output "portal_user_pool_id" {
  description = "Cognito user pool of the portal (scripts/portal-user.sh)."
  value       = aws_cognito_user_pool.portal.id
}
