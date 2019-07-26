terraform {
  backend "remote" {
    hostname = "app.terraform.io"
    organization = "Future-Infrastructure"
    workspaces {
      name = "snaps-k8s"
    }
  }
}
