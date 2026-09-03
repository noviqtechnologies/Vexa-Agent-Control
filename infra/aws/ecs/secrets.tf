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
}
