/*

   tf-aws_microservice_stack

   Filename:
   full-microservice-stack.tf

   Summary:
   A near 1:1 Ruby to Terraform port of "ruby-aws-microservice"[1]
   Launches a stack that is load-balanced, auto-scaling, auto-healing, and contains a microservice (NGINX) in AWS.

   Details:
   Initial Terraform code that can construct, build, launch and version control a base AWS stack from scratch.  This
   "stack"[2][3] is created within a single AWS "Region"[4] that uses two AWS "Availability Zones"[5].  For this
   stack, a single "VPC"[6] is used and as a demo, the "microservice"[7][8] deployed is NGINX, which is a part of
   an "auto scaling group"[9] and "launch configuration"[10].  The "ELB"[11] that is configured and deployed is an
   "Application Load Balancer"[12] (ALB) that demostrates the usage of "ALB Target Groups"[13] and "ALB
   Listeners"[14].

   How to execute:
   1) $ terraform plan
   2) $ terraform apply

   How to clean up (nuke entire stack):
   1) $ terraform destroy

   Notes:
   1) Uses 'ubuntu' as the default AWS SSH keypair name ... search/replace as needed.

   Action Items:
   1) Create modules for each portion of the stack from this code (e.g. network-core (VPC, subnets, rtbls, ...),
      security-base (SGs, ...), nat-base (NAT instances w/ HA, ...), web (nginx, ...), loadbalance-base (alb,
      listeners, targetgroups, ...), resilience-base (auto-scaling-groups, launch configurations, ...).
   2) Add variables for non-static "stuff".  A variables.tf will be created within each stack module.
   3) Ensure the microservice root directory is clean with only a main.tf, variables.tf, terraform.tfvars and
      modules sub directory.
   4) Employ Terraform lifecycle blocks and test create_before_destroy in action. Resources that utilize the
      create_before_destroy key can only depend on other resources that also include create_before_destroy.
      Referencing a resource that does not include create_before_destroy will result in a dependency graph cycle.
   5) Severely test and understand the version control aspect of Terraform in massive depth until comfortable
      imagining Terraform being used in production.

   References:
   1) https://github.com/codytubbs/ruby-aws-microservice
   2) http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacks.html
   3) https://en.wikipedia.org/wiki/Solution_stack
   4) https://aws.amazon.com/about-aws/global-infrastructure/
   5) http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html
   6) http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html
   7) https://d0.awsstatic.com/whitepapers/microservices-on-aws.pdf
   8) https://aws.amazon.com/blogs/compute/microservice-delivery-with-amazon-ecs-and-application-load-balancers/
   9) http://docs.aws.amazon.com/autoscaling/latest/userguide/AutoScalingGroup.html
   10) http://docs.aws.amazon.com/autoscaling/latest/userguide/LaunchConfiguration.html
   11) https://aws.amazon.com/elasticloadbalancing/
   12) https://aws.amazon.com/elasticloadbalancing/applicationloadbalancer/
   13) http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html
   14) http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html

   Author:
   Cody Tubbs (codytubbs+tams@gmail.com) July 2017
   https://github.com/codytubbs

*/

/*
   Internal action-item notes for stack build and execution:
   Terraform execution run-list:
   0.  Supply Credentials
   1.  Create VPC
   2.  Create two public subnets (one per AZ)
   3.  Create two private subnets (one per AZ)
   4.  Create Internet Gateway (IGW)
   5.  Create public routing table (RTBL)
   6.  Create public Internet route for public routing table
   7.  Create private routing table (RTBL)
   8.  Create Route Table Association for Public Subnets
   9.  Create Route Table Association for Private Subnets
  10.  Create and setup Security Groups (SGs) (Testing only, will lock down after successful tests)
  11.  Create and launch two NAT instances (one per VZ)
  12.  Create route in private route table for instances to use NAT instances as the gateway for Internet access
  13.  Create ALB (Application Load Balancer)
  13.1 Create ALB target group
  13.2 Create ALB listener
  14.  Create Launch Configs (LC) for nginx
  15.  Create Auto-scaling-groups (ASG) for nginx microservice
*/


# 0. Supply Credentials
# creds can supposedly be excluded and found within ~/.aws/credentials. [tested successfully]
provider "aws" {
  region  = "us-west-2"
  profile = "default" # override default profile
  #access_key = "nil" # Supply from credentials file, never hardcoded within Terraform code
  #secret_key = "nil" # ''
  #shared_credentials_file = "/Users/cody/.aws/credentials" # override default location
}

# 1. Create VPC
resource "aws_vpc" "vpc_one_resource" {
  cidr_block           = "10.100.0.0/16"
  enable_dns_support   = true # Default is true if not specified
  enable_dns_hostnames = true # Default is false if not specified
  tags = {
    Name = "Custom VPC one"
  }
}

# 2. Create two public subnets (one per AZ)
# Public subnet for AZ #1 (10.100.1.0/24)
resource "aws_subnet" "public_subnet_one_resource" {
  vpc_id                  = "${aws_vpc.vpc_one_resource.id}"
  cidr_block              = "10.100.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-west-2a"
  tags = {
    Name =  "Public Subnet us-west-2a"
  }
}
# Public subnet for AZ #2 (10.100.2.0/24)
resource "aws_subnet" "public_subnet_two_resource" {
  vpc_id                  = "${aws_vpc.vpc_one_resource.id}"
  cidr_block              = "10.100.2.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-west-2b"
  tags = {
    Name =  "Public Subnet us-west-2b"
  }
}

# 3. Create two private subnets (one per AZ)
# Private subnet for AZ #1 (10.100.100.0/24)
resource "aws_subnet" "private_subnet_one_resource" {
  vpc_id                  = "${aws_vpc.vpc_one_resource.id}"
  cidr_block              = "10.100.100.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "us-west-2a"
  tags = {
    Name =  "Private Subnet us-west-2a"
  }
}
# Private subnet for AZ #2 (10.100.200.0/24)
resource "aws_subnet" "private_subnet_two_resource" {
  vpc_id                  = "${aws_vpc.vpc_one_resource.id}"
  cidr_block              = "10.100.200.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "us-west-2b"
  tags = {
    Name =  "Private Subnet us-west-2b"
  }
}

# 4. Create Internet Gateway (IGW)
resource "aws_internet_gateway" "igw_one_resource" {
  vpc_id = "${aws_vpc.vpc_one_resource.id}"
  tags {
    Name = "Internet Gateway for Custom VPC one"
  }
}

# 5. Create public routing table (RTBL)
resource "aws_route_table" "public_rtbl_one_resource" {
  vpc_id = "${aws_vpc.vpc_one_resource.id}"

  tags {
    Name = "Public Route Table for Custom VPC one"
  }
}

# 6. Create public Internet route for public routing table
resource "aws_route" "public_inet_route_one_resource" {
  route_table_id         = "${aws_route_table.public_rtbl_one_resource.id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = "${aws_internet_gateway.igw_one_resource.id}"
}

# 7. Create private routing table (RTBL)
resource "aws_route_table" "private_rtbl_one_resource" {
  vpc_id = "${aws_vpc.vpc_one_resource.id}"
  tags {
    Name = "Private Route Table for Custom VPC one"
  }
}

# 8. Create Route Table Associations for Public Subnets
# associate public subnet #1 to VPC #1 via insertion in to public route table #1
resource "aws_route_table_association" "public_subnet_one_vpc_one_association_resource" {
  subnet_id      = "${aws_subnet.public_subnet_one_resource.id}"
  route_table_id = "${aws_route_table.public_rtbl_one_resource.id}" # public route #1 to vpc1 (pub rtbl #1)
}
# associate public subnet #2 to VPC #1 via insertion in to public route table #1
resource "aws_route_table_association" "public_subnet_two_vpc_one_association_resource" {
  subnet_id      = "${aws_subnet.public_subnet_two_resource.id}"
  route_table_id = "${aws_route_table.public_rtbl_one_resource.id}" # public route #2 to vpc1 (pub rtbl #1)
}

# 9. Create Route Table Associations for Private Subnets
# associate private subnet #1 to VPC #1 via insertion in to private route table #1
resource "aws_route_table_association" "private_subnet_one_vpc_one_association_resource" {
  subnet_id      = "${aws_subnet.private_subnet_one_resource.id}"
  route_table_id = "${aws_route_table.private_rtbl_one_resource.id}" # priv route #1 to vpc1 (priv rtbl #1)
}
# associate private subnet #2 to VPC #1 via insertion in to private route table #1
resource "aws_route_table_association" "private_subnet_two_vpc_one_association_resource" {
  subnet_id      = "${aws_subnet.private_subnet_two_resource.id}"
  route_table_id = "${aws_route_table.private_rtbl_one_resource.id}" # priv route #2 to vpc1 (priv rtbl #1)
}

# 10. Create and setup Security Groups (SGs) (Testing only, will lock down after successful tests)
resource "aws_security_group" "sg_allow_all_in_out_tcp_vpc_one_resource" {
  name        = "allow_all_in_out_tcp"
  description = "Allow all in out tcp traffic"
  vpc_id      = "${aws_vpc.vpc_one_resource.id}"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags {
    Name = "allow_all_in_out_tcp"
  }
}

# 11. Create and launch two NAT instances (one per VZ)
# NAT instance for private traffic to route through for private subnet one in us-west-2a
# NOTE: Make sure to change the iptables rule in the user_data to reflect the correct address space, if needed
resource "aws_instance" "nat_instance_one_resource" {
  ami                                  = "ami-efd0428f"
  count                                = 1
  associate_public_ip_address          = true
  vpc_security_group_ids               = ["${aws_security_group.sg_allow_all_in_out_tcp_vpc_one_resource.id}"]
  subnet_id                            = "${aws_subnet.public_subnet_one_resource.id}"
  instance_type                        = "t2.micro"
  availability_zone                    = "us-west-2a"
  source_dest_check                    = false
  ebs_optimized                        = false
  placement_group                      = ""
  monitoring                           = false
  disable_api_termination              = false
  instance_initiated_shutdown_behavior = "terminate"
  key_name                             = "ubuntu" # TODO: Turn into a variable
  user_data = <<-EOF
              #!/bin/bash -ex
              export DEBIAN_FRONTEND=noninteractive
              apt-get -q=2 update && apt-get -q=2 upgrade
              sysctl -w net.ipv4.ip_forward=1
              sysctl -w net.ipv4.conf.eth0.send_redirects=0
              iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
              iptables -t nat -A POSTROUTING -s 192.168.0.0/16 -o eth0 -j MASQUERADE
              iptables -t nat -A POSTROUTING -s 172.0.0.0/8 -o eth0 -j MASQUERADE
              EOF
  tags {
    Name = "NAT Instance One"
  }
  depends_on = ["aws_security_group.sg_allow_all_in_out_tcp_vpc_one_resource"]
}
# NAT instance for private traffic to route through for private subnet two in us-west-2b
# NOTE: Make sure to change the iptables rule(s) in the user_data to reflect the correct address space, if different.
resource "aws_instance" "nat_instance_two_resource" {
  ami                                  = "ami-efd0428f"
  count                                = 1
  associate_public_ip_address          = true
  vpc_security_group_ids               = ["${aws_security_group.sg_allow_all_in_out_tcp_vpc_one_resource.id}"]
  subnet_id                            = "${aws_subnet.public_subnet_two_resource.id}"
  instance_type                        = "t2.micro"
  availability_zone                    = "us-west-2b"
  source_dest_check                    = false
  ebs_optimized                        = false
  placement_group                      = ""
  monitoring                           = false
  disable_api_termination              = false
  instance_initiated_shutdown_behavior = "terminate"
  key_name                             = "ubuntu" # TODO: Turn into a variable
  user_data = <<-EOF
              #!/bin/bash -ex
              export DEBIAN_FRONTEND=noninteractive
              apt-get -q=2 update && apt-get -q=2 upgrade
              sysctl -w net.ipv4.ip_forward=1
              sysctl -w net.ipv4.conf.eth0.send_redirects=0
              iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
              iptables -t nat -A POSTROUTING -s 192.168.0.0/16 -o eth0 -j MASQUERADE
              iptables -t nat -A POSTROUTING -s 172.0.0.0/8 -o eth0 -j MASQUERADE
              EOF
  tags {
    Name = "NAT Instance Two"
  }
  depends_on = ["aws_security_group.sg_allow_all_in_out_tcp_vpc_one_resource"]
}

# 12. Create route in private route table for instances to use NAT instances as the gateway for Internet access
resource "aws_route" "private_route_for_nat_instance_one_resource" {
  route_table_id         = "${aws_route_table.private_rtbl_one_resource.id}"
  destination_cidr_block = "0.0.0.0/0"
  instance_id            = "${aws_instance.nat_instance_one_resource.id}"
  depends_on             = ["aws_instance.nat_instance_one_resource", "aws_instance.nat_instance_two_resource"]
}
# Not needed... get exact reason why, or test taking down NAT instance #1 and see if traffic still goes out NAT instance #2
#resource "aws_route" "private_route_for_nat_instance_two_resource" {
#  route_table_id         = "${aws_route_table.private_rtbl_one_resource.id}"
#  destination_cidr_block = "0.0.0.0/0"
#  instance_id            = "${aws_instance.nat_instance_two_resource.id}"
#  depends_on             = ["aws_instance.nat_instance_two_resource"]
#}

# 13. Create ALB (Application Load Balancer)
resource "aws_alb" "alb_vpc_one_resource" {
  name                       = "alb-nginx"
  security_groups            = ["${aws_security_group.sg_allow_all_in_out_tcp_vpc_one_resource.id}"]
  subnets                    = ["${aws_subnet.public_subnet_one_resource.id}","${aws_subnet.public_subnet_two_resource.id}"]
  enable_deletion_protection = false
  ip_address_type            = "ipv4"
  tags {
    Environment = "development"
  }
  depends_on = ["aws_security_group.sg_allow_all_in_out_tcp_vpc_one_resource"]
}

# 13.1 Create ALB target group
resource "aws_alb_target_group" "alb_target_group_vpc_one_resource" {
  name       = "alb-target-group-nginx"
  port       = 80
  protocol   = "HTTP"
  vpc_id     = "${aws_vpc.vpc_one_resource.id}"
  health_check {
    path                = "/"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200"
  }
}

# 13.2 Create ALB listener
resource "aws_alb_listener" "alb_listener_vpc_one_resource" {
  load_balancer_arn = "${aws_alb.alb_vpc_one_resource.arn}"
  protocol          = "HTTP"
  port              = 80
  default_action {
    type             = "forward" # Required
    target_group_arn = "${aws_alb_target_group.alb_target_group_vpc_one_resource.arn}"
  }
  depends_on = ["aws_alb_target_group.alb_target_group_vpc_one_resource"]
  #depends_on = ["aws_autoscaling_group.asg_nginx_one_resource"]
}

# 14. Create Launch Configs (LC) for nginx
resource "aws_launch_configuration" "lc_nginx_one_resource" {
  name                        = "lc-nginx"
  image_id                    = "ami-efd0428f"
  instance_type               = "t2.micro"
  associate_public_ip_address = false
  security_groups             = ["${aws_security_group.sg_allow_all_in_out_tcp_vpc_one_resource.id}"]
  enable_monitoring           = true # Enable for CloudWatch monitoring (60 sec intervals? Verify this...)
  key_name                    = "ubuntu" # TODO: Turn into a variable
  user_data = <<-EOF
              #!/bin/bash -ex
              export DEBIAN_FRONTEND=noninteractive
              apt-get -q=2 update && apt-get -q=2 upgrade
              apt-get -q=2 install nginx
              URL=http://169.254.169.254/latest/meta-data
              cat >> /var/www/html/index.html <<XXX
              <meta http-equiv=refresh content=2 /><br>
              FROM: Launch Configuration / ASG<br>
              INSTANCE ID: $(curl $URL/instance-id)<br>
              PUBLIC IP: [NONE], using NAT instances<br>
              INTERNAL IP: $(curl $URL/local-ipv4)<br>
              XXX
              EOF
  depends_on = ["aws_security_group.sg_allow_all_in_out_tcp_vpc_one_resource"]
}

# 15. Create Auto-scaling-groups (ASG) for nginx microservice
resource "aws_autoscaling_group" "asg_nginx_one_resource" {
  name                      = "asg-nginx"
  launch_configuration      = "${aws_launch_configuration.lc_nginx_one_resource.name}"
  availability_zones        = ["us-west-2a", "us-west-2b"]
  vpc_zone_identifier       = ["${aws_subnet.private_subnet_one_resource.id}", "${aws_subnet.private_subnet_two_resource.id}"]
  #load_balancers           = ["${aws_alb.alb_vpc_one_resource.name}"] # FOR CLB ONLY! Will cause TF to error if an ALB name/id is passed here.
  target_group_arns         = ["${aws_alb_target_group.alb_target_group_vpc_one_resource.arn}"] # For ALB's
  health_check_grace_period = 300
  health_check_type         = "ELB"
  min_size                  = 4
  max_size                  = 8
  desired_capacity          = 4
  termination_policies      = ["ClosestToNextInstanceHour", "OldestInstance", "OldestLaunchConfiguration"] # Change to our needs after testing...
  tag {
    key                  = "Name"
    value                = "asg_one_nginx_microservice"
    propagate_at_launch  = true
  }
  depends_on = ["aws_alb.alb_vpc_one_resource", "aws_instance.nat_instance_one_resource", "aws_instance.nat_instance_two_resource"]
}

output "alb_dns_name" {
  value = "${aws_alb.alb_vpc_one_resource.dns_name}"
}