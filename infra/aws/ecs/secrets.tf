# ─── Random Secret Generators ───────────────────────────────────────────────────

resource "random_password" "gateway_secret" {
  length  = 32
  special = false
}

resource "random_password" "policy_read_secret" {
  length  = 32
  special = false
}

resource "random_password" "postgres_password" {
  length  = 24
  special = false
}

resource "random_password" "session_secret" {
  length  = 32
  special = false
}

resource "random_id" "encryption_secret" {
  byte_length = 32
}

locals {
  gateway_secret     = var.gateway_secret != "" ? var.gateway_secret : random_password.gateway_secret.result
  policy_read_secret = var.policy_read_secret != "" ? var.policy_read_secret : random_password.policy_read_secret.result
  postgres_password  = var.postgres_password != "" ? var.postgres_password : random_password.postgres_password.result
  encryption_secret  = var.encryption_secret != "" ? var.encryption_secret : random_id.encryption_secret.hex
  session_secret     = var.session_secret != "" ? var.session_secret : random_password.session_secret.result

  effective_database_url = var.database_url != "" ? var.database_url : (
    var.enable_rds ? "postgres://${var.postgres_user}:${random_password.rds_password[0].result}@${aws_db_instance.postgres[0].endpoint}/${var.postgres_db}?sslmode=require" : "postgres://${var.postgres_user}:${local.postgres_password}@127.0.0.1:5432/${var.postgres_db}?sslmode=disable"
  )
}
