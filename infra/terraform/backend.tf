terraform {
  backend "gcs" {
    prefix = "walrus/terraform/state"
  }
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
  required_version = ">= 1.9"
}

provider "google" {
  project = var.project_id
  region  = var.region
}
