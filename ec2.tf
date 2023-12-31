# https://registry.terraform.io/providers/hashicorp/aws/latest/docs
# you'll want to change the default region
provider "aws" {
  profile = "default"
  region = "eu-west-2"
}

# Find the AMI ID
data "aws_ami" "freebsd" {
  most_recent = true

  filter {
    name   = "name"
    values = ["FreeBSD*13.2*"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
  
  owners = ["aws-marketplace"]
}

#output "freebsd_ami_id" {
#  value = data.aws_ami.freebsd.id
#}

# Variables. Create terraform.tf vars or pass --var var=VALUE to terraform apply
variable "num" {
  default = 1
  description = "Number of ec2 instances to run"
}

variable "type" {
  description = "t4g.nano 512mb; .micro 1gb; .medium 4gb x2gd.medium cheapest 16gb"
}

variable "key" {
  description = "SSH key name. Must exist in ec2"
}

variable "root_disk" {
  description = "Root disk size"
}

# https://aws.amazon.com/marketplace/pp/prodview-csz7hkwk5a4ls
# aws cli to find ami IDs:
# aws ec2 describe-images --owners aws-marketplace --filters "Name=name,Values=*FreeBSD*" "Name=state,Values=available" "Name=architecture,Values=arm64" --query 'Images[*].{ID:ImageId, Name:Name}' --region eu-west-2
# also useful:
# aws ec2 describe-instance-types --query "InstanceTypes[?starts_with(InstanceType, 't4g')].[InstanceType, MemoryInfo.SizeInMiB]" --output json | jq '.[] | [.[0], .[1] / 1024]' --region eu-west-2 

resource "aws_instance" "nodes" {
    # bump size on root disk
    ebs_block_device {
      device_name = "/dev/sda1"
      volume_size = var.root_disk
      volume_type = "gp2"
      delete_on_termination = true
    }

  count         = var.num
  ami           = data.aws_ami.freebsd.id
  instance_type = var.type
  key_name      = var.key
}

# if you want to add an extra disk at a later point 
# resource "aws_ebs_volume" "storage" {
#   availability_zone = aws_instance.nodes[0].availability_zone
#   size              = 10
#   tags = {
#     Name = "storage"
#   }
# }
# 
# resource "aws_volume_attachment" "ebs_att_1" {
#   device_name = "/dev/sdh"
#   volume_id   = aws_ebs_volume.storage.id
#   instance_id = aws_instance.nodes[0].id
# }

output "instance_public_dns" {
  value = aws_instance.nodes.*.public_dns
}

