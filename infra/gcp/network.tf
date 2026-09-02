# ─── VPC & Serverless VPC Access (Optional Enterprise Private Isolation) ──────

resource "google_compute_network" "vpc" {
  count                   = var.enable_vpc ? 1 : 0
  project                 = var.gcp_project_id
  name                    = "vpc-${local.name_prefix}"
  auto_create_subnetworks = false
  description             = "Custom Virtual Private Cloud (VPC) for AgentControl private services"

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "subnet" {
  count                    = var.enable_vpc ? 1 : 0
  project                  = var.gcp_project_id
  name                     = "snet-${local.name_prefix}"
  ip_cidr_range            = var.vpc_cidr
  region                   = var.gcp_region
  network                  = google_compute_network.vpc[0].id
  private_ip_google_access = true
}

resource "google_vpc_access_connector" "connector" {
  count         = var.enable_vpc ? 1 : 0
  project       = var.gcp_project_id
  name          = "vpc-conn-${var.environment}"
  region        = var.gcp_region
  ip_cidr_range = var.connector_cidr
  network       = google_compute_network.vpc[0].name
  min_instances = 2
  max_instances = 3
  machine_type  = "e2-micro"

  depends_on = [
    google_project_service.apis,
    google_compute_network.vpc
  ]
}

resource "google_compute_firewall" "allow_internal" {
  count       = var.enable_vpc ? 1 : 0
  project     = var.gcp_project_id
  name        = "fw-${local.name_prefix}-allow-internal"
  network     = google_compute_network.vpc[0].name
  description = "Allow internal traffic within AgentControl VPC network"

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "8080", "8081", "8400", "5432"]
  }

  source_ranges = [var.vpc_cidr, var.connector_cidr]
}
