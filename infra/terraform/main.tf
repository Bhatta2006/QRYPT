# =============================================================================
# SVT System — Terraform Main Configuration
# =============================================================================
# Provisions GKE Autopilot, Cloud SQL, Memorystore Redis, GCS, and KMS
# =============================================================================

terraform {
  required_version = ">= 1.7"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.20"
    }
  }

  backend "gcs" {
    bucket = "svt-terraform-state"
    prefix = "terraform/state"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# =============================================================================
# VPC Network
# =============================================================================
resource "google_compute_network" "svt_vpc" {
  name                    = "svt-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "svt_subnet" {
  name          = "svt-subnet"
  ip_cidr_range = "10.0.0.0/20"
  region        = var.region
  network       = google_compute_network.svt_vpc.id

  secondary_ip_range {
    range_name    = "svt-pods"
    ip_cidr_range = "10.4.0.0/14"
  }

  secondary_ip_range {
    range_name    = "svt-services"
    ip_cidr_range = "10.8.0.0/20"
  }

  private_ip_google_access = true
}

# =============================================================================
# GKE Autopilot Cluster
# =============================================================================
resource "google_container_cluster" "svt_cluster" {
  name     = "svt-cluster"
  location = var.region

  enable_autopilot = true

  network    = google_compute_network.svt_vpc.id
  subnetwork = google_compute_subnetwork.svt_subnet.id

  ip_allocation_policy {
    cluster_secondary_range_name  = "svt-pods"
    services_secondary_range_name = "svt-services"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  release_channel {
    channel = "REGULAR"
  }

  deletion_protection = var.deletion_protection
}

# =============================================================================
# Cloud SQL — PostgreSQL 16 (Private IP)
# =============================================================================
resource "google_compute_global_address" "private_ip_range" {
  name          = "svt-private-ip-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.svt_vpc.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.svt_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]
}

resource "google_sql_database_instance" "svt_postgres" {
  name             = "svt-postgres"
  region           = var.region
  database_version = "POSTGRES_16"

  depends_on = [google_service_networking_connection.private_vpc_connection]

  settings {
    tier              = var.db_tier
    availability_type = "REGIONAL"
    disk_size         = 50
    disk_type         = "PD_SSD"
    disk_autoresize   = true

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.svt_vpc.id
      enable_private_path_for_google_cloud_services = true
    }

    backup_configuration {
      enabled                        = true
      start_time                     = "02:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = 30
        retention_unit   = "COUNT"
      }
    }

    database_flags {
      name  = "timescaledb.telemetry_level"
      value = "off"
    }

    maintenance_window {
      day          = 7  # Sunday
      hour         = 3
      update_track = "stable"
    }
  }

  deletion_protection = var.deletion_protection
}

resource "google_sql_database" "svt_db" {
  name     = "svt"
  instance = google_sql_database_instance.svt_postgres.name
}

resource "google_sql_user" "svt_app" {
  name     = "svt_app"
  instance = google_sql_database_instance.svt_postgres.name
  password = var.db_app_password
}

# =============================================================================
# Memorystore — Redis 7
# =============================================================================
resource "google_redis_instance" "svt_redis" {
  name           = "svt-redis"
  tier           = "STANDARD_HA"
  memory_size_gb = 2
  region         = var.region
  redis_version  = "REDIS_7_0"

  authorized_network = google_compute_network.svt_vpc.id

  auth_enabled            = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"

  redis_configs = {
    maxmemory-policy = "allkeys-lru"
  }

  maintenance_policy {
    weekly_maintenance_window {
      day = "SUNDAY"
      start_time {
        hours   = 3
        minutes = 0
      }
    }
  }
}

# =============================================================================
# GCS Bucket — Backups
# =============================================================================
resource "google_storage_bucket" "svt_backups" {
  name          = "${var.project_id}-svt-backups"
  location      = var.region
  storage_class = "STANDARD"
  force_destroy = false

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }

  uniform_bucket_level_access = true
}

# =============================================================================
# KMS — Envelope Encryption for Issuer Keys
# =============================================================================
resource "google_kms_key_ring" "svt_keyring" {
  name     = "svt-keyring"
  location = "global"
}

resource "google_kms_crypto_key" "svt_issuer_keys" {
  name     = "svt-issuer-keys"
  key_ring = google_kms_key_ring.svt_keyring.id

  rotation_period = "7776000s"  # 90 days

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# =============================================================================
# Service Account for GKE workloads
# =============================================================================
resource "google_service_account" "svt_backend_sa" {
  account_id   = "svt-backend"
  display_name = "SVT Backend Service Account"
}

resource "google_project_iam_member" "svt_backend_kms" {
  project = var.project_id
  role    = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member  = "serviceAccount:${google_service_account.svt_backend_sa.email}"
}

resource "google_project_iam_member" "svt_backend_sql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.svt_backend_sa.email}"
}

resource "google_project_iam_member" "svt_backend_gcs" {
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.svt_backend_sa.email}"
}
