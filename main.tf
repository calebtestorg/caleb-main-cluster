variable project_name {}
variable instance_type {}
variable instance_count {}
variable cidr_block {}

locals {
  name = "${terraform.workspace}-${var.project_name}"
}

provider aws {
  region = "ap-southeast-2"
}

terraform {
  backend s3 {
    region = "ap-southeast-2"
    key = "caleb-main-cluster/state.tfstate"
    bucket = "terraform-state-20180702094442696700000001"
  }
}

// Network

resource aws_vpc vpc {
  cidr_block = "${var.cidr_block}"
  enable_dns_hostnames = "true"
  enable_dns_support = "true"
  tags {
    Name = "${local.name}"
  }
}

resource aws_subnet sn {
  count = 2
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, count.index)}"
  availability_zone = "${count.index % 2 == 0 ? "ap-southeast-2a": "ap-southeast-2b"}"
  vpc_id = "${aws_vpc.vpc.id}"
}

resource aws_internet_gateway igw {
  vpc_id = "${aws_vpc.vpc.id}"
  tags {
    Name = "${local.name}"
  }
}

resource aws_route route {
  route_table_id = "${aws_vpc.vpc.main_route_table_id}"
  gateway_id = "${aws_internet_gateway.igw.id}"
  destination_cidr_block = "0.0.0.0/0"
}

resource aws_security_group instance_sg {
  name = "${local.name}-instance-sg"
  vpc_id = "${aws_vpc.vpc.id}"
  ingress {
    from_port = 6000
    protocol = "tcp"
    to_port = 7000
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }
  ingress {
    from_port = 22
    protocol = "tcp"
    to_port = 22
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }
  egress {
    from_port = 0
    protocol = "-1"
    to_port = 0
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }
}

// Elastic Container Service (ECS)

data aws_iam_policy_document ecs_logs {

  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams"
    ]
    resources = [
      "arn:aws:logs:*:*:*"
    ]
  }
}

resource aws_iam_role_policy ecs_logs {
  name = "${local.name}-ecs-logs"
  role = "${aws_iam_role.ec2_role.id}"
  policy = "${data.aws_iam_policy_document.ecs_logs.json}"
}

resource aws_ecs_cluster ecs_cluster {
  name = "${local.name}-cluster"
}

// ========= EC2 ==========

data aws_iam_policy_document ec2_role {

  statement {
    actions = [
      "sts:AssumeRole"
    ]
    principals {
      identifiers = [
        "ec2.amazonaws.com"
      ]
      type = "Service"
    }
  }
}

resource aws_iam_role ec2_role {
  assume_role_policy = "${data.aws_iam_policy_document.ec2_role.json}"
}

data aws_iam_policy_document ec2_ecs_role_policy {

  statement {
    actions = [
      "ecs:CreateCluster",
      "ecs:DeregisterContainerInstance",
      "ecs:DiscoverPollEndpoint",
      "ecs:Poll",
      "ecs:RegisterContainerInstance",
      "ecs:StartTelemetrySession",
      "ecs:Submit*",
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "*"
    ]
  }
}

resource aws_iam_role_policy ec2_ecs_role_policy {
  name = "${local.name}-ec2-ecs"
  role = "${aws_iam_role.ec2_role.id}"
  policy = "${data.aws_iam_policy_document.ec2_ecs_role_policy.json}"
}

resource aws_iam_instance_profile ec2_instance_profile {
  name = "${local.name}-ec2-instance-profile"
  role = "${aws_iam_role.ec2_role.name}"
}

resource tls_private_key ssh_k {
  algorithm = "RSA"
  rsa_bits = 4096
}

resource aws_key_pair kp {
  key_name = "${local.name}"
  public_key = "${tls_private_key.ssh_k.public_key_openssh}"
}

// NOTE: Changes here require the instance to be terminated and rebuilt in order for ecs to work.
// Ensure this happends by tainting the resource before applying
// Example: terraform taint aws_instance.ecs
resource aws_instance ecs {
  count = "${var.instance_count}"
  ami = "ami-bc04d5de"
  instance_type = "${var.instance_type}"
  subnet_id = "${element(aws_subnet.sn.*.id, count.index % 2)}"
  associate_public_ip_address = true
  iam_instance_profile = "${aws_iam_instance_profile.ec2_instance_profile.id}"
  vpc_security_group_ids = [
    "${aws_security_group.instance_sg.id}"
  ]
  key_name = "${aws_key_pair.kp.key_name}"
  user_data = <<EOF
  #!/bin/bash
  echo ECS_CLUSTER=${aws_ecs_cluster.ecs_cluster.name} >> /etc/ecs/ecs.config
  EOF
  tags {
    Name = "${local.name}"
  }
}

resource null_resource instance_provisioner {
  count = "${var.instance_count}"

  provisioner file {
    source = "./awslogs.conf"
    destination = "/tmp/awslogs.conf"

    connection {
      type = "ssh"
      user = "ec2-user"
      host = "${element(aws_instance.ecs.*.public_ip, count.index)}"
      private_key = "${tls_private_key.ssh_k.private_key_pem}"
    }
  }

  provisioner remote-exec {
    inline = [
      "sudo yum install -y awslogs",
      "sudo mv /etc/awslogs/awslogs.conf /etc/awslogs/awslogs.conf.bak",
      "sudo mv /tmp/awslogs.conf /etc/awslogs/awslogs.conf",
      "sudo sed -i -e \"s/us-east-1/ap-southeast-2/g\" /etc/awslogs/awscli.conf",
      "sudo sed -i -e \"s/{cluster}/${aws_ecs_cluster.ecs_cluster.name}/g\" /etc/awslogs/awslogs.conf",
      "sudo sed -i -e \"s/{container_instance_id}/${element(aws_instance.ecs.*.id, count.index)}/g\" /etc/awslogs/awslogs.conf",
      "sudo service awslogs start",
      "sudo chkconfig awslogs on"
    ]

    connection {
      type = "ssh"
      user = "ec2-user"
      host = "${element(aws_instance.ecs.*.public_ip, count.index)}"
      private_key = "${tls_private_key.ssh_k.private_key_pem}"
    }
  }
}

output ecs_cluster_id {
  value = "${aws_ecs_cluster.ecs_cluster.id}"
}

output vpc_id {
  value = "${aws_vpc.vpc.id}"
}

output sn_0_id {
  value = "${aws_subnet.sn.0.id}"
}

output sn_1_id {
  value = "${aws_subnet.sn.1.id}"
}

output instance_ids {
  value = "${aws_instance.ecs.*.id}"
}
