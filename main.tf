# AWS Secrets Manager done right — Terraform
# Full pattern: KMS CMK -> secret -> automatic RDS rotation -> least-privilege
# app role -> optional cross-account resource policy.
#
# Usage:
#   terraform init && terraform apply -var="db_host=<rds-endpoint>" \
#     -var="partner_account_id=<optional-account-id>"

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-southeast-1"
}

variable "project" {
  description = "Name prefix for all resources"
  type        = string
  default     = "shopdb"
}

variable "db_host" {
  description = "RDS endpoint the rotation Lambda connects to"
  type        = string
}

variable "db_engine" {
  description = "Engine for the rotation template (mysql | postgresql | ...)"
  type        = string
  default     = "mysql"
}

variable "rotation_days" {
  description = "Rotate the credential this often"
  type        = number
  default     = 30
}

variable "partner_account_id" {
  description = "Optional partner AWS account allowed to READ the secret"
  type        = string
  default     = ""
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# 1. KMS customer-managed key — envelope encryption for the secret
# ---------------------------------------------------------------------------
resource "aws_kms_key" "secrets" {
  description             = "${var.project}: encrypts Secrets Manager secrets"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  # Key policy: the rotation role and the app role may use the key;
  # account root retains administration. Tighten further in production.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowRootAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "AllowSecretRolesUseKey"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.app_reader.arn,
            aws_iam_role.rotation.arn,
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*",
        ]
        Resource = "*"
      },
    ]
  })

  tags = { Name = "${var.project}-secrets-cmk" }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.project}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# ---------------------------------------------------------------------------
# 2. The secret itself — encrypted with OUR CMK, not the AWS-managed key
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "db_credentials" {
  name        = "${var.project}/db-credentials"
  description = "RDS ${var.db_engine} credentials, rotated every ${var.rotation_days} days"
  kms_key_id  = aws_kms_key.secrets.arn

  # Keep old versions briefly so a bad rotation can be rolled back.
  recovery_window_in_days = 7

  tags = { Name = "${var.project}-db-credentials" }
}

# ---------------------------------------------------------------------------
# 3. Automatic rotation — AWS RDS template Lambda, every N days
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret_rotation" "db" {
  secret_id           = aws_secretsmanager_secret.db_credentials.id
  rotation_lambda_arn = aws_lambda_function.rotation.arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }

  depends_on = [aws_lambda_permission.allow_secrets_manager]
}

resource "aws_iam_role" "rotation" {
  name = "${var.project}-secret-rotation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "rotation" {
  name = "${var.project}-secret-rotation-policy"
  role = aws_iam_role.rotation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Read/write ONLY this secret during rotation
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:UpdateSecretVersionStage"]
        Resource = aws_secretsmanager_secret.db_credentials.arn
      },
      {
        # Allow the Lambda to reach the DB security group is a network
        # concern (VPC config below), not an IAM one.
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      },
    ]
  })
}

# Rotation Lambda from the AWS-provided serverless app template.
# Deploy the "SecretsManagerRDSPostgreSQLRotationSingleUser" (or MySQL
# equivalent) SAR app once, then point this at its function ARN.
resource "aws_lambda_function" "rotation" {
  function_name = "${var.project}-secret-rotation"
  role          = aws_iam_role.rotation.arn

  # Placeholder package — replace with the SAR template build.
  filename         = "rotation_placeholder.zip"
  source_code_hash = filebase64sha256("rotation_placeholder.zip")
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60

  vpc_config {
    # Rotation Lambda MUST live in the DB VPC subnets with a SG
    # allowed to reach the RDS port.
    subnet_ids         = var.rotation_subnet_ids
    security_group_ids = var.rotation_security_group_ids
  }

  environment {
    variables = {
      SECRETS_MANAGER_ENDPOINT = "https://secretsmanager.${data.aws_region.current.name}.amazonaws.com"
    }
  }
}

variable "rotation_subnet_ids" {
  type = list(string)
}
variable "rotation_security_group_ids" {
  type = list(string)
}

resource "aws_lambda_permission" "allow_secrets_manager" {
  statement_id  = "AllowSecretsManagerInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotation.function_name
  principal     = "secretsmanager.amazonaws.com"
}

# ---------------------------------------------------------------------------
# 4. Least-privilege app role — reads ONLY this secret
# ---------------------------------------------------------------------------
resource "aws_iam_role" "app_reader" {
  name = "${var.project}-app-secret-reader"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" } # or ec2 / lambda
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "app_reader" {
  name = "${var.project}-app-secret-reader-policy"
  role = aws_iam_role.app_reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      Resource = aws_secretsmanager_secret.db_credentials.arn
      # NOTE: no wildcard. One statement per secret. kms:Decrypt is granted
      # separately via the KMS key policy above.
    }]
  })
}

# ---------------------------------------------------------------------------
# 5. Optional: cross-account read via resource policy (not IAM!)
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret_policy" "partner_read" {
  count      = var.partner_account_id != "" ? 1 : 0
  secret_arn = aws_secretsmanager_secret.db_credentials.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PartnerReadOnly"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.partner_account_id}:root" }
      Action    = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      Resource  = "*"
      Condition = {
        # Partner still needs kms:Decrypt on OUR CMK (separate grant),
        # and ideally MFA for human break-glass:
        Bool = { "aws:MultiFactorAuthPresent" = "true" }
      }
    }]
  })
}

# ---------------------------------------------------------------------------
# 6. DR: replicate the secret to the failover region (block on the PRIMARY
#    secret — replication is initiated from the primary, not a second resource)
# ---------------------------------------------------------------------------
# NOTE: the replica block lives on the primary secret above. Uncomment and
# adjust once you have created the DR-region CMK:
#
# resource "aws_secretsmanager_secret" "db_credentials" {
#   ...
#   replica {
#     region     = "ap-southeast-3"
#     kms_key_id = aws_kms_key.secrets_dr.arn
#   }
# }

provider "aws" {
  alias  = "dr"
  region = "ap-southeast-3" # Jakarta DR region
}

resource "aws_kms_key" "secrets_dr" {
  provider                = aws.dr
  description             = "${var.project}: DR-region CMK for secret replicas"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "secret_arn" {
  description = "ARN of the primary secret — hand this to app modules"
  value       = aws_secretsmanager_secret.db_credentials.arn
}

output "app_role_arn" {
  description = "Attach to ECS task roles / Lambda execution roles / instance profiles"
  value       = aws_iam_role.app_reader.arn
}

output "kms_key_alias" {
  value = aws_kms_alias.secrets.name
}
