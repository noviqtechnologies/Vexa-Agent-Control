# ─── Azure Container Registry (ACR) — Optional Private Registry ───────────────
# Equivalent to ECR in the AWS deployment. Disabled by default to use public GHCR images.

locals {
  # ACR names must be alphanumeric only and 5-50 characters
  acr_name = replace("acr${local.name_prefix}${random_string.suffix.result}", "-", "")
}

resource "azurerm_container_registry" "acr" {
  count               = var.acr_enabled ? 1 : 0
  name                = local.acr_name
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Basic"
  admin_enabled       = true
  tags                = local.default_tags
}
