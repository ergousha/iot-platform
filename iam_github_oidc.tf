# ---------------------------------------------------------------------------
# GitHub OIDC Provider and Role
# ---------------------------------------------------------------------------

locals {
  # The OIDC subject of each product's repository, Environment `release`
  # only (which only protected main may deploy to; the signing key lives
  # there). GitHub puts the immutable owner and repository ids in the subject,
  # so a renamed or re-created repository with the same name cannot assume
  # the role.
  github_oidc_subs = {
    for id, p in local.products :
    id => "repo:${split("/", p.github_repository)[0]}@${var.github_owner_id}/${split("/", p.github_repository)[1]}@${p.github_repository_id}:environment:release"
  }

  # The commits of the SDK's release workflow a release may run in, from
  # release_workflow_commits.json (commit SHA -> note). Only these: `@*`
  # would also accept the commit of an unmerged pull request, which GitHub
  # serves from a public repository like any other. CI checks that each one
  # is on the SDK's main (scripts/check-release-workflow-commits.sh).
  release_workflow_commits = keys(jsondecode(file("${path.module}/release_workflow_commits.json")))
  release_workflow_refs    = [for sha in local.release_workflow_commits : "${var.release_workflow}@${sha}"]
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"] # GitHub's standard thumbprints
}

# One role per product, trusted by that product's repository only, and only
# from inside the SDK's reusable release workflow at an approved commit
# (job_workflow_ref): neither a workflow edited in the product repository nor
# one pinned to an unapproved SDK commit can assume it. A release of one
# product therefore cannot write another's firmware.
data "aws_iam_policy_document" "github_assume_role" {
  for_each = local.products

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.github_oidc_subs[each.key]]
    }
    # Callers pin the workflow by commit SHA, which job_workflow_ref carries
    # as its ref: only the approved commits.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:job_workflow_ref"
      values   = local.release_workflow_refs
    }
  }
}

resource "aws_iam_role" "github_actions" {
  for_each = local.products

  name               = each.value.github_actions_role_name
  assume_role_policy = data.aws_iam_policy_document.github_assume_role[each.key].json

  lifecycle {
    precondition {
      condition     = length(local.release_workflow_commits) > 0 && alltrue([for sha in local.release_workflow_commits : can(regex("^[0-9a-f]{40}$", sha))])
      error_message = "release_workflow_commits.json maps full 40-character lowercase commit SHAs of the SDK's release workflow to notes, and lists at least one."
    }
  }
}

data "aws_iam_policy_document" "github_actions_policy" {
  for_each = local.products

  # Only the product's own releases/<product>/ prefix. GetObject lets a re-run
  # compare what is already there (uploads are If-None-Match: *, so a
  # published release is never overwritten). No SSM, no IoT: images are built
  # without AWS, and the OTA controller verifies every upload's signature.
  statement {
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.firmware.arn}/releases/${each.key}/*"]
  }
}

resource "aws_iam_role_policy" "github_actions_s3" {
  for_each = local.products

  name   = "${var.project_name}-github-actions-s3-policy"
  role   = aws_iam_role.github_actions[each.key].id
  policy = data.aws_iam_policy_document.github_actions_policy[each.key].json
}

# The single role became the legacy product's (the gateway's) role.
moved {
  from = aws_iam_role.github_actions
  to   = aws_iam_role.github_actions["gateway"]
}

moved {
  from = aws_iam_role_policy.github_actions_s3
  to   = aws_iam_role_policy.github_actions_s3["gateway"]
}
