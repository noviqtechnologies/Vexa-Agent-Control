# ─── Virtual Network & ACA Delegated Subnet (Optional Enterprise Isolation) ───

resource "azurerm_virtual_network" "vnet" {
  count               = var.enable_vnet_integration ? 1 : 0
  name                = "vnet-${local.name_prefix}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = [var.vnet_cidr]
  tags                = local.default_tags
}

resource "azurerm_subnet" "aca" {
  count                = var.enable_vnet_integration ? 1 : 0
  name                 = "snet-aca-${var.environment}"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet[0].name
  address_prefixes     = [var.aca_subnet_cidr]

  delegation {
    name = "aca-delegation"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# ─── Network Security Group ───────────────────────────────────────────────────

resource "azurerm_network_security_group" "aca_nsg" {
  count               = var.enable_vnet_integration ? 1 : 0
  name                = "nsg-${local.name_prefix}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = local.default_tags

  security_rule {
    name                       = "AllowHTTPInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["80", "443", "8080", "8081", "8400"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "aca" {
  count                     = var.enable_vnet_integration ? 1 : 0
  subnet_id                 = azurerm_subnet.aca[0].id
  network_security_group_id = azurerm_network_security_group.aca_nsg[0].id
}
