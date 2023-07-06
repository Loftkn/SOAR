terraform {
  required_providers {
    libvirt = {
      source = "dmacvicar/libvirt"
    }
  }
}

provider "libvirt" {
  uri = "qemu:///system"
}

variable "hostname" {
  type    = list(string)
  default = ["manager", "worker-1"]
}

variable "domain" { default = "local" }

variable "memoryMB" { default = 4096 }

variable "cpu" { default = 4 }

variable "image" {
  type = list(string)
  default = ["images/jammy-server-cloudimg-amd64-disk-kvm.img", "images/jammy-server-cloudimg-amd64-disk-kvm.img"]
}


variable "ips" {
  type = list
  default = ["192.168.122.11", "192.168.122.22"]
}

variable "macs" {
  type = list
  default = ["52:54:00:50:99:c5", "52:54:00:50:99:c6"]
}

resource "libvirt_volume" "os_image" {
  count = length(var.hostname)
  name = "os_image.${var.hostname[count.index]}"
  pool = "default"
  source = "${var.image[count.index]}"
  format = "qcow2"
}

resource "libvirt_cloudinit_disk" "commoninit" {
  count = length(var.hostname)
  name = "${var.hostname[count.index]}-commoninit.iso"
  pool = "default"
  user_data = templatefile("${path.module}/cloud_init.cfg", {
    host_name = var.hostname[count.index]
  }) 

  network_config = templatefile("${path.module}/network_config_dhcp.cfg", {
     interface = "ens01"
     ip_addr   = "${var.ips[count.index]}"
     mac_addr = "${var.macs[count.index]}"
  })
}

# Define KVM domain to create
resource "libvirt_domain" "domain-centos" {
  count = length(var.hostname) 
  name = "${var.hostname[count.index]}"
  memory = var.memoryMB
  vcpu   = var.cpu

disk {
    volume_id = element(libvirt_volume.os_image.*.id, count.index)
  }

  cloudinit = libvirt_cloudinit_disk.commoninit[count.index].id
  
  network_interface {
    network_name = "default"
    addresses    = [var.ips[count.index]]
    mac          = var.macs[count.index]
  }
 
  console {
    type = "pty"
    target_type = "serial"
    target_port = "0"
  }

  graphics {
    type = "spice"
    listen_type = "address"
    autoport = true
  }
  
  provisioner "remote-exec" {
    inline = ["sudo yum update -y", "sudo yum install python3 -y", "echo Done!"]

    connection {
      host        = var.ips[count.index]
      type        = "ssh"
      user        = "vmadmin"
      password = "linux"
    }
  }

#  provisioner "local-exec" {
#    command = var.playbook_ansible[count.index] 
#  } 
}
