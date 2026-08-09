provider "azurerm" {
  features {}
}

provider "random" {}

# ─── Unique Resource Suffix & Local Values ────────────────────────────────────

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Auto-generate secure secrets if not explicitly provided by the user
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

resource "random_id" "encryption_secret" {
  byte_length = 32
}

locals {
  resource_group_name = var.resource_group_name != "" ? var.resource_group_name : "rg-agentwall-${var.environment}-${var.azure_region}"
  name_prefix         = "agentwall-${var.environment}"

  gateway_secret     = var.gateway_secret != "" ? var.gateway_secret : random_password.gateway_secret.result
  policy_read_secret = var.policy_read_secret != "" ? var.policy_read_secret : random_password.policy_read_secret.result
  postgres_password  = var.postgres_password != "" ? var.postgres_password : random_password.postgres_password.result
  encryption_secret  = var.encryption_secret != "" ? var.encryption_secret : random_id.encryption_secret.hex

  default_tags = merge({
    Project     = "agentwall"
    Environment = var.environment
    ManagedBy   = "terraform"
  }, var.tags)
}

# ─── Resource Group ───────────────────────────────────────────────────────────

resource "azurerm_resource_group" "rg" {
  name     = local.resource_group_name
  location = var.azure_region
  tags     = local.default_tags
}

# ─── Log Analytics Workspace (Monitoring & Ingestion) ─────────────────────────

resource "azurerm_log_analytics_workspace" "logs" {
  name                = "log-${local.name_prefix}-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.default_tags
}

# ─── Azure Container Apps Environment ($0 Control Plane) ──────────────────────

resource "azurerm_container_app_environment" "aca_env" {
  name                           = "cae-${local.name_prefix}-${random_string.suffix.result}"
  location                       = azurerm_resource_group.rg.location
  resource_group_name            = azurerm_resource_group.rg.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.logs.id
  infrastructure_subnet_id       = var.enable_vnet_integration ? azurerm_subnet.aca[0].id : null
  internal_load_balancer_enabled = false
  tags                           = local.default_tags
}
