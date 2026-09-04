# ─── GCP Project & Region Configuration ───────────────────────────────────────

variable "gcp_project_id" {
  description = "The Google Cloud Project ID where all AgentControl resources will be deployed."
  type        = string
  default     = "your-gcp-project-id"
}

variable "gcp_project_number" {
  description = "Optional GCP Project Number (e.g. 123456789012)."
  type        = number
  default     = null
}

variable "gcp_region" {
  description = "Google Cloud region for Cloud Run services (e.g. europe-west1, us-central1, asia-east1)."
  type        = string
  default     = "europe-west1"
}

variable "environment" {
  description = "Deployment environment identifier (e.g. stage, dev, prod)."
  type        = string
  default     = "stage"
}

# ─── Container Images ─────────────────────────────────────────────────────────

variable "container_image" {
  description = "Container image for the AgentControl Gateway proxy."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentcontrol:latest"
}

variable "control_plane_ui_image" {
  description = "Container image for the AgentControl Enterprise Control Plane Frontend UI."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentcontrol-dashboard-frontend:latest"
}

variable "control_plane_api_image" {
  description = "Container image for the AgentControl Enterprise Control Plane Dashboard API."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentcontrol-dashboard-api:latest"
}

variable "control_plane_db_image" {
  description = "Container image for the AgentControl PostgreSQL Database with initial migrations."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentcontrol-db:latest"
}

# ─── Sizing, Scaling & Cost-Optimized Compute ─────────────────────────────────

variable "min_instances" {
  description = "Minimum number of Cloud Run instances (0 = scale-to-zero / $0 idle compute for stage)."
  type        = number
  default     = 0
}

variable "max_instances" {
  description = "Maximum number of container instances for auto-scaling under load."
  type        = number
  default     = 3
}

variable "gateway_cpu" {
  description = "vCPU allocated to the Gateway container (e.g. '1', '2')."
  type        = string
  default     = "1"
}

variable "gateway_memory" {
  description = "Memory allocated to the Gateway container (e.g. '256Mi', '512Mi', '1Gi')."
  type        = string
  default     = "256Mi"
}

variable "api_cpu" {
  description = "vCPU allocated to the Dashboard API container."
  type        = string
  default     = "1"
}

variable "api_memory" {
  description = "Memory allocated to the Dashboard API container."
  type        = string
  default     = "256Mi"
}

variable "ui_cpu" {
  description = "vCPU allocated to the Control Plane UI container."
  type        = string
  default     = "1"
}

variable "ui_memory" {
  description = "Memory allocated to the Control Plane UI container."
  type        = string
  default     = "256Mi"
}

variable "db_cpu" {
  description = "vCPU allocated to the PostgreSQL sidecar container."
  type        = string
  default     = "1"
}

variable "db_memory" {
  description = "Memory allocated to the PostgreSQL sidecar container."
  type        = string
  default     = "256Mi"
}

# ─── Access & Security ────────────────────────────────────────────────────────

variable "allow_unauthenticated" {
  description = "When true, enables public access to Gateway and Control Plane UI via Cloud Run IAM role roles/run.invoker for allUsers."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Whether to enable Cloud Run service deletion protection to prevent accidental teardown."
  type        = bool
  default     = false
}

variable "gateway_url" {
  description = "Explicit Gateway URL for API environment configuration (if empty, dynamically resolved)."
  type        = string
  default     = ""
}

# ─── Networking & VPC Integration ─────────────────────────────────────────────

variable "enable_vpc" {
  description = "When true, provisions a custom VPC and Serverless VPC Access Connector. Set to false for staging to maximize cost savings ($0 networking)."
  type        = bool
  default     = false
}

variable "vpc_cidr" {
  description = "CIDR block for the custom VPC (used when enable_vpc = true)."
  type        = string
  default     = "10.10.0.0/16"
}

variable "connector_cidr" {
  description = "CIDR block for the Serverless VPC Access connector (must be an unused /28 block)."
  type        = string
  default     = "10.10.8.0/28"
}

# ─── Google Artifact Registry (GAR) ───────────────────────────────────────────

variable "gar_enabled" {
  description = "When true, provisions a dedicated Google Artifact Registry Docker repository with automated retention policies."
  type        = bool
  default     = false
}

# ─── Secrets & Database Credentials ───────────────────────────────────────────

variable "gateway_secret" {
  description = "Shared secret authenticating telemetry pushes from the CLI to the API. If left empty, an auto-generated random token is used."
  type        = string
  default     = ""
  sensitive   = true
}

variable "policy_read_secret" {
  description = "Shared secret used by the Gateway to pull active policies from the API. If left empty, an auto-generated random token is used."
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

variable "session_secret" {
  description = "Cookie signing secret for dashboard session authentication. If left empty, an auto-generated random token is used."
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
  description = "PostgreSQL database name for AgentControl."
  type        = string
  default     = "agentcontrol"
}

variable "database_url" {
  description = "Optional connection string for a persistent external PostgreSQL database (e.g. Cloud SQL, Neon, Supabase, RDS). When provided, the dashboard API connects to this persistent database and retains all logs, telemetry, and audit history across deployments and scale-to-zero restarts."
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_cloud_sql" {
  description = "When true, provisions a managed Google Cloud SQL PostgreSQL 16 instance. Guarantees permanent persistence for provider keys, virtual keys, audit logs, and spend data across Cloud Run deployments and scale-to-zero restarts."
  type        = bool
  default     = false
}

variable "cloud_sql_tier" {
  description = "Machine tier for the managed Cloud SQL PostgreSQL instance (e.g. 'db-f1-micro' for stage ~$7.50/mo, 'db-g1-small' ~$15/mo)."
  type        = string
  default     = "db-f1-micro"
}

variable "cloud_sql_disk_size_gb" {
  description = "Initial SSD disk size in GB for the managed Cloud SQL instance."
  type        = number
  default     = 10
}

# ─── Custom Labels ────────────────────────────────────────────────────────────

variable "labels" {
  description = "Custom Google Cloud labels merged with default deployment labels."
  type        = map(string)
  default     = {}
}
