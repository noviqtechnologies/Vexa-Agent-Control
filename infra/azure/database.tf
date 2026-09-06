# ─── Azure Database for PostgreSQL Flexible Server (Optional Persistence) ──────
# Provisions a managed Azure PostgreSQL Flexible Server instance when enable_azure_postgres = true.
# Guarantees permanent persistence for provider keys, virtual keys, audit logs, and spend data.
# Default is false to minimize stage cost ($0 compute / ACA internal DB).

resource "random_password" "azure_postgres_password" {
  count   = var.enable_azure_postgres ? 1 : 0
  length  = 24
  special = false
}

resource "azurerm_postgresql_flexible_server" "postgres" {
  count                  = var.enable_azure_postgres ? 1 : 0
  name                   = "${local.name_prefix}-pg-${random_string.suffix.result}"
  resource_group_name    = azurerm_resource_group.rg.name
  location               = azurerm_resource_group.rg.location
  version                = "16"
  administrator_login    = var.postgres_user
  administrator_password = random_password.azure_postgres_password[0].result
  sku_name               = var.azure_postgres_sku
  storage_mb             = var.azure_postgres_storage_mb
  zone                   = "1"
  tags                   = local.default_tags
}

resource "azurerm_postgresql_flexible_server_database" "agentcontrol" {
  count     = var.enable_azure_postgres ? 1 : 0
  name      = var.postgres_db
  server_id = azurerm_postgresql_flexible_server.postgres[0].id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_azure_services" {
  count            = var.enable_azure_postgres ? 1 : 0
  name             = "AllowAzureServices"
  server_id        = azurerm_postgresql_flexible_server.postgres[0].id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}
