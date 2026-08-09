# ─── Azure Region & Environment ───────────────────────────────────────────────

variable "azure_region" {
  description = "Azure region where all resources will be provisioned (e.g. westeurope, eastus, centralus)."
  type        = string
  default     = "westeurope"
}

variable "environment" {
  description = "Deployment environment name (e.g. dev, staging, prod)."
  type        = string
  default     = "dev"
}

variable "resource_group_name" {
  description = "Name of the Azure Resource Group. If left empty, it defaults to rg-agentwall-<environment>."
  type        = string
  default     = ""
}

# ─── Container Images ─────────────────────────────────────────────────────────

variable "container_image" {
  description = "Container image for the AgentWall Gateway proxy."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentwall:latest"
}

variable "control_plane_ui_image" {
  description = "Container image for the AgentWall Enterprise Control Plane Frontend UI."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentwall-dashboard-frontend:latest"
}

variable "control_plane_api_image" {
  description = "Container image for the AgentWall Enterprise Control Plane Dashboard API."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentwall-dashboard-api:latest"
}

variable "control_plane_db_image" {
  description = "Container image for the AgentWall PostgreSQL Database with initial migrations."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentwall-db:latest"
}

# ─── Networking & VNet Integration ────────────────────────────────────────────

variable "enable_vnet_integration" {
  description = "When true, deploys a dedicated VNet and delegated ACA subnet. When false, runs in Azure-managed serverless network for lowest complexity and cost."
  type        = bool
  default     = false
}

variable "vnet_cidr" {
  description = "CIDR block for the Azure Virtual Network (used when enable_vnet_integration = true)."
  type        = string
  default     = "10.10.0.0/16"
}

variable "aca_subnet_cidr" {
  description = "CIDR block for the ACA infrastructure delegated subnet (minimum /23 required by Azure Container Apps)."
  type        = string
  default     = "10.10.0.0/23"
}

# ─── Azure Container Registry (ACR) ───────────────────────────────────────────

variable "acr_enabled" {
  description = "When true, provisions a private Azure Container Registry (ACR) with managed identity authentication."
  type        = bool
  default     = false
}

# ─── Sizing & Auto-Scaling ────────────────────────────────────────────────────

variable "min_replicas" {
  description = "Minimum number of container replicas (set to 0 for scale-to-zero in idle dev, or 1 for always-on)."
  type        = number
  default     = 1
}

variable "max_replicas" {
  description = "Maximum number of container replicas for auto-scaling under load."
  type        = number
  default     = 5
}

variable "gateway_cpu" {
  description = "vCPU allocated to the Gateway container (e.g. 0.25, 0.5, 1.0)."
  type        = number
  default     = 0.25
}

variable "gateway_memory" {
  description = "Memory allocated to the Gateway container (e.g. 0.5Gi, 1.0Gi, 2.0Gi)."
  type        = string
  default     = "0.5Gi"
}

variable "api_cpu" {
  description = "vCPU allocated to the Dashboard API container."
  type        = number
  default     = 0.25
}

variable "api_memory" {
  description = "Memory allocated to the Dashboard API container."
  type        = string
  default     = "0.5Gi"
}

variable "ui_cpu" {
  description = "vCPU allocated to the Control Plane UI container."
  type        = number
  default     = 0.25
}

variable "ui_memory" {
  description = "Memory allocated to the Control Plane UI container."
  type        = string
  default     = "0.5Gi"
}

variable "db_cpu" {
  description = "vCPU allocated to the Database container."
  type        = number
  default     = 0.25
}

variable "db_memory" {
  description = "Memory allocated to the Database container."
  type        = string
  default     = "0.5Gi"
}

# ─── Secrets & Credentials ────────────────────────────────────────────────────

variable "gateway_secret" {
  description = "Shared secret authenticating telemetry pushes from the CLI to the API. If left empty, an auto-generated random token is used."
  type        = string
  default     = ""
  sensitive   = true
}

variable "policy_read_secret" {
  description = "Shared secret used by the Gateway to pull the active policy from the API. If left empty, an auto-generated random token is used."
  type        = string
  default     = ""
  sensitive   = true
}

variable "encryption_secret" {
  description = "Master 32-byte hex encryption key (64 hex characters) for provider API key storage. If left empty, an auto-generated 64-char key is used."
  type        = string
  default     = ""
  sensitive   = true
}

variable "postgres_user" {
  description = "PostgreSQL username for the control plane database."
  type        = string
  default     = "agentwall"
}

variable "postgres_password" {
  description = "PostgreSQL password for the control plane database. If left empty, an auto-generated password is used."
  type        = string
  default     = ""
  sensitive   = true
}

variable "postgres_db" {
  description = "PostgreSQL database name for AgentWall."
  type        = string
  default     = "agentwall"
}

# ─── Resource Tags ────────────────────────────────────────────────────────────

variable "tags" {
  description = "Custom resource tags merged with standard deployment tags."
  type        = map(string)
  default     = {}
}
