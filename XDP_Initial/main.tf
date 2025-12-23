# Essential AWS Traffic Mirror Configuration
# This configuration focuses only on the core components needed for traffic mirroring
# It uses existing VPC and subnet infrastructure

# Security Group for VXLAN Gateway
resource "aws_security_group" "vxlan_gateway" {
  name        = "vxlan-gateway-sg"
  description = "Security group for VXLAN gateway instance"
  vpc_id      = var.vpc_id

  # SSH access
  ingress {
    from_port   = 1035
    to_port     = 1035
    protocol    = "tcp"
    cidr_blocks = ["172.30.82.0/23"]
  }

  # VXLAN traffic
  ingress {
    from_port   = 4789
    to_port     = 4789
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 1035
    to_port     = 1035
    protocol    = "tcp"
    cidr_blocks = ["10.2.72.0/24"]
  }

  # HTTP for health checks
  ingress {
    from_port   = 1035
    to_port     = 1035
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "vxlan-gateway-sg"
  }
}

# XDP Migration Control
variable "enable_xdp_migration" {
  description = "Enable XDP migration (true) or keep legacy netfilter (false)"
  type        = bool
  default     = true
}

# User data script for VXLAN gateway instance
locals {
  # XDP-enabled user data
  xdp_user_data = <<-EOS
#!/bin/bash
set -e

cat << 'EOF' > /etc/netplan/55-mirror.yaml
network:
    version: 2
    ethernets:
        ens6:
            dhcp4: false
EOF
netplan apply

DESTPATH="/etc/networkd-dispatcher/routable.d/50-configure-mirror.sh"

cat << 'EOF' > $DESTPATH
#!/bin/bash

# We only want to run this when the main interface comes up
MAIN_INT=ens5
SECONDARY_ENI=ens6
GCP_PREFIX=100.64.0.0/10
AWS_IPSEC_VM_IP=${var.aws_ipsec_vm_ip}
AWS_IPSEC_VM_PORT=${var.aws_ipsec_vm_port}
SECONDARY_ENI_MAC=$(ip link sh ens6 | awk '/link\/ether/{print $2}')

# Install XDP dependencies instead of netfilter
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r)
sudo apt-get install -y bpftool make git

if [ $IFACE = $MAIN_INT ]; then
        DEFAULT_GW=$(ip route | awk '/default via/{print $3}')
        echo 1 > /proc/sys/net/ipv4/ip_forward
        # Add br0
        ip link add br0 type bridge
        # Set br0 mac
        ip link set br0 address $SECONDARY_ENI_MAC
        # Add vxlan interface
        ip link add vxlan1 type vxlan id 1 dstport 4789
        # Add vxlan interface to bridge
        ip link set vxlan1 master br0
        # Add secondary ENI to bridge
        ip link set $SECONDARY_ENI master br0
        # Bring up interfaces
        ip link set up dev vxlan1
        ip link set up dev ens6
        ip link set up dev br0
        # Get an IP for the secondary
        dhclient br0
        SECONDARY_ENI_IP=$(ip addr sh dev br0 | awk '/inet /{print $2}')

        # Add iptables rule
        iptables -t nat -A PREROUTING -p udp -m udp --dport 31765 -j DNAT --to-destination $${AWS_IPSEC_VM_IP}:$${AWS_IPSEC_VM_PORT}
        # Add ebtables rule
        ebtables -t nat -A PREROUTING -p IPv4 -i vxlan1 --ip-proto udp --ip-dport 31765 -j dnat --to-dst $SECONDARY_ENI_MAC --dnat-target ACCEPT

        # Deploy XDP codebase to /opt/xdp
        mkdir -p /opt/xdp
        cd /opt/xdp

        # Create XDP source files inline (for simplicity)
        cat << 'XDPBPF' > udp_df_modifier.bpf.c
// XDP program content would be embedded here
// For demo: using a simple version
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define TARGET_PORT 31765
#define MIN_PACKET_SIZE 1400
#define IP_DF 0x4000

SEC("xdp")
int udp_df_modifier(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP) return XDP_PASS;
    
    int ip_hdr_len = iph->ihl * 4;
    if ((void *)((char *)iph + ip_hdr_len) > data_end) return XDP_PASS;
    
    struct udphdr *udph = (struct udphdr *)((char *)iph + ip_hdr_len);
    if ((void *)(udph + 1) > data_end) return XDP_PASS;
    
    if (bpf_ntohs(udph->dest) == TARGET_PORT && bpf_ntohs(iph->tot_len) > MIN_PACKET_SIZE) {
        if (iph->frag_off & bpf_htons(IP_DF)) {
            iph->frag_off &= ~bpf_htons(IP_DF);
            iph->check = 0;  // Will be recalculated by hardware/kernel
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
XDPBPF

        # Create simple loader
        cat << 'XDPLOADER' > udp_df_loader.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <signal.h>

static int ifindex;
static int prog_fd = -1;
static volatile int running = 1;

void cleanup(int sig) {
    running = 0;
    if (prog_fd >= 0 && ifindex > 0) {
        bpf_set_link_xdp_fd(ifindex, -1, 0);
    }
    exit(0);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    
    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }
    
    struct bpf_object *obj = bpf_object__open("udp_df_modifier.bpf.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "udp_df_modifier");
    if (!prog) {
        fprintf(stderr, "Failed to find program\n");
        return 1;
    }
    
    prog_fd = bpf_program__fd(prog);
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
        perror("bpf_set_link_xdp_fd");
        return 1;
    }
    
    printf("XDP program attached to %s\n", argv[1]);
    while (running) sleep(1);
    
    return 0;
}
XDPLOADER

        # Create Makefile
        cat << 'XDPMAKE' > Makefile
all: udp_df_modifier.bpf.o udp_df_loader

udp_df_modifier.bpf.o: udp_df_modifier.bpf.c
	clang -O2 -target bpf -c udp_df_modifier.bpf.c -o udp_df_modifier.bpf.o

udp_df_loader: udp_df_loader.c
	gcc -o udp_df_loader udp_df_loader.c -lbpf

clean:
	rm -f udp_df_modifier.bpf.o udp_df_loader
XDPMAKE

        # Build and deploy XDP
        make clean && make
        
        # Create systemd service for XDP
        cat << 'XDPSVC' > /etc/systemd/system/xdp-udp-modifier.service
[Unit]
Description=XDP UDP DF Modifier
After=network.target

[Service]
Type=simple
ExecStart=/opt/xdp/udp_df_loader br0
Restart=always
RestartSec=5
WorkingDirectory=/opt/xdp

[Install]
WantedBy=multi-user.target
XDPSVC

        # Start XDP service (replaces netfilter NFQUEUE)
        systemctl daemon-reload
        systemctl enable xdp-udp-modifier.service
        systemctl start xdp-udp-modifier.service
        
        # Network configuration (same as before)
        ip link set br0 mtu 1400
        ip route add $GCP_PREFIX via $DEFAULT_GW dev br0
        ip route del default via $DEFAULT_GW dev br0
        
        echo "XDP UDP DF modifier deployed on br0"
fi
EOF

chmod 755 $DESTPATH
systemctl restart networkd-dispatcher
EOS

  # Legacy netfilter user data (for rollback)
  vxlan_user_data = <<-EOS
#!/bin/bash

cat << 'EOF' > /etc/netplan/55-mirror.yaml
network:
    version: 2
    ethernets:
        ens6:
            dhcp4: false
EOF
netplan apply

DESTPATH="/etc/networkd-dispatcher/routable.d/50-configure-mirror.sh"

cat << 'EOF' > $DESTPATH
#!/bin/bash

# We only want to run this when the main interface comes up
MAIN_INT=ens5
SECONDARY_ENI=ens6
GCP_PREFIX=100.64.0.0/10
AWS_IPSEC_VM_IP=${var.aws_ipsec_vm_ip}
AWS_IPSEC_VM_PORT=${var.aws_ipsec_vm_port}
SECONDARY_ENI_MAC=$(ip link sh ens6 | awk '/link\/ether/{print $2}')

sudo apt-get update
sudo apt-get install build-essential libnfnetlink-dev libnetfilter-queue-dev -y  # need for netfilter c++ script to operate

if [ $IFACE = $MAIN_INT ]; then
        DEFAULT_GW=$(ip route | awk '/default via/{print $3}')
        echo 1 > /proc/sys/net/ipv4/ip_forward
        # Add br0
        ip link add br0 type bridge
        # Set br0 mac
        ip link set br0 address $SECONDARY_ENI_MAC
        # Add vxlan interface
        ip link add vxlan1 type vxlan id 1 dstport 4789
        # Add vxlan interface to bridge
        ip link set vxlan1 master br0
        # Add secondary ENI to bridge
        ip link set $SECONDARY_ENI master br0
        # Bring up interfaces
        ip link set up dev vxlan1
        ip link set up dev ens6
        ip link set up dev br0
        # Get an IP for the secondary
        dhclient br0
        SECONDARY_ENI_IP=$(ip addr sh dev br0 | awk '/inet /{print $2}')

        # Add iptables rule
        iptables -t nat -A PREROUTING -p udp -m udp --dport 31765 -j DNAT --to-destination $${AWS_IPSEC_VM_IP}:$${AWS_IPSEC_VM_PORT}
        # Add ebtables rule
        ebtables -t nat -A PREROUTING -p IPv4 -i vxlan1 --ip-proto udp --ip-dport 31765 -j dnat --to-dst $SECONDARY_ENI_MAC --dnat-target ACCEPT

        # Netfilter queue
        sudo iptables -t mangle -A PREROUTING -i br0 -p udp --dport 31765 -j NFQUEUE --queue-num 0
        # Need to pre-fragment the packet to send out the unset df bit packet
        ip link set br0 mtu 1400
        # Add route for $GCP_PREFIX via $DEFAULT_GW
        ip route add $GCP_PREFIX via $DEFAULT_GW dev br0
        # Delete default route out br0
        ip route del default via $DEFAULT_GW dev br0

        cat << 'EOT' > /home/ubuntu/modify_udp_df.cpp
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>

// Callback function to process packets
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    unsigned char *pktData;
    int len = nfq_get_payload(nfa, &pktData);
    if (len >= 0) {
        struct iphdr *ip = (struct iphdr *)pktData;
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(pktData + ip->ihl * 4);
            // Only modify if packet length > 1400 bytes
            if (ntohs(udp->dest) == 31765 && ntohs(ip->tot_len) > 1400) {
                if (ip->frag_off & htons(0x4000)) { // DF bit is set
                    ip->frag_off &= ~htons(0x4000); // Unset DF bit
                    ip->check = 0; // Invalidate IP checksum
                    udp->check = 0; // Invalidate UDP checksum

                    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ip->saddr, src_ip, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &ip->daddr, dst_ip, INET_ADDRSTRLEN);
                    std::cout << "Modified large UDP packet: ID=" << ntohs(ip->id)
                              << ", Src=" << src_ip
                              << ", Dst=" << dst_ip
                              << ", DF bit unset" << std::endl;
                }
            }
        }
    }

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;
    return nfq_set_verdict(qh, id, NF_ACCEPT, len, pktData);
}

int main() {
    // --- FIX FOR SERVICE LOGGING ---
    // Disable buffering on std::cout and std::cerr.
    // This ensures all output is written immediately to the systemd journal.
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);
    // -----------------------------

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    h = nfq_open();
    if (!h) {
        std::cerr << "Error during nfq_open()" << std::endl;
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        std::cerr << "Error during nfq_unbind_pf()" << std::endl;
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        std::cerr << "Error during nfq_bind_pf()" << std::endl;
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, nullptr);
    if (!qh) {
        std::cerr << "Error during nfq_create_queue()" << std::endl;
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "Can't set packet_copy mode" << std::endl;
        exit(1);
    }

    fd = nfq_fd(h);
    std::cout << "Waiting for packets in NFQUEUE 0..." << std::endl;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
EOT

        # C++ code compile
        cd /home/ubuntu/
        g++ -o modify_udp_df modify_udp_df.cpp -lnetfilter_queue

# Use a "here document" to write the multi-line configuration
cat << 'EOM' > /etc/systemd/system/modify_udp.service
[Unit]
Description=Service to unset DF bit on large UDP packets
After=network.target

[Service]
# IMPORTANT: Use the full path to your executable
ExecStart=/home/ubuntu/modify_udp_df
WorkingDirectory=/home/ubuntu
User=root
Restart=always
RestartSec=5

# Let systemd handle the logs correctly
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOM
        # Reload the systemd manager configuration
        sudo systemctl daemon-reload

        # Enable the service to start automatically at boot
        sudo systemctl enable modify_udp.service

        # Start the service now
        sudo systemctl start modify_udp.service

fi
EOF

chmod 755 $DESTPATH
systemctl restart networkd-dispatcher
EOS
}

# Secondary ENI for VXLAN gateway
#resource "aws_network_interface" "vxlan_secondary" {
#  subnet_id       = var.private_subnet_id
#  security_groups = [aws_security_group.vxlan_gateway.id]
#  source_dest_check = false
#
#  tags = {
#    Name = "vxlan-gateway-secondary"
#  }
#}

# VXLAN Gateway Instance - Single EC2 instance
#resource "aws_instance" "mirror_gateway" {
#  ami                    = var.base_ami
#  instance_type          = var.ec2_instance_type
#  subnet_id              = var.private_subnet_id
#  vpc_security_group_ids = [aws_security_group.vxlan_gateway.id]
#  user_data              = local.vxlan_user_data

#  tags = {
#    Name = "mirror-gateway-instance"
#    Environment   = var.environment
#    Product       = var.product
#    Component     = var.component
#    Region        = "us-west-2"
#    AppPlatform   = "cloud"
#    Subcomponent  = "flow"
#    InfraPlatform = "ec2"
#  }

# Disable source/destination check for traffic mirroring
#  source_dest_check = false
#}

# Attach secondary ENI to VXLAN gateway
#resource "aws_network_interface_attachment" "vxlan_secondary" {
#  instance_id          = aws_instance.mirror_gateway.id
#  network_interface_id = aws_network_interface.vxlan_secondary.id
#  device_index         = 1
#}

# Network Load Balancer
resource "aws_lb" "traffic_mirror" {
  name               = "traffic-mirror-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = var.private_subnet_ids

  tags = {
    Name = "traffic-mirror-nlb"
  }
}

# Target Group for VXLAN
resource "aws_lb_target_group" "aws-mirror-tg" {
  name     = "mirror-tg"
  port     = 4789
  protocol = "UDP"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    interval            = 30
    port                = 1035
    protocol            = "TCP"
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = {
    Name = "aws-mirror-tg"
  }
}

# Target Group Attachment
#resource "aws_lb_target_group_attachment" "vxlan" {
#  target_group_arn = aws_lb_target_group.aws-mirror-tg.arn
#  target_id        = aws_instance.mirror_gateway.id
#  port             = 4789
#}

# NLB Listener for VXLAN
resource "aws_lb_listener" "mirror-listener" {
  load_balancer_arn = aws_lb.traffic_mirror.arn
  port              = 4789
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.aws-mirror-tg.arn
  }
}

# Traffic Mirror Target
resource "aws_ec2_traffic_mirror_target" "mirror-target" {
  network_load_balancer_arn = aws_lb.traffic_mirror.arn
  description               = "Traffic mirror target pointing to NLB"

  tags = {
    Name = "nlb-mirror-target"
  }
}

# Traffic Mirror Filter
resource "aws_ec2_traffic_mirror_filter" "mirror-filter" {
  description = "Traffic mirror filter for all traffic"

  tags = {
    Name = "main-mirror-filter"
  }
}

# Filter rules - Mirror all traffic
# resource "aws_ec2_traffic_mirror_filter_rule" "ingress" {
#   count = length(var.filter_cidrs)
#   description              = "Mirror all ingress traffic"
#   traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.mirror-filter.id
#   destination_cidr_block   = "0.0.0.0/0"
#   source_cidr_block        = var.filter_cidrs[count.index]
#   rule_number              = 100
#   rule_action              = "accept"
#   traffic_direction        = "ingress"
# }

resource "aws_ec2_traffic_mirror_filter_rule" "egress" {
  count                    = length(var.filter_cidrs)
  description              = "Mirror all egress traffic"
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.mirror-filter.id
  destination_cidr_block   = "0.0.0.0/0"
  protocol                 = 17
  source_cidr_block        = var.filter_cidrs[count.index]
  rule_number              = 100 + count.index
  rule_action              = "accept"
  traffic_direction        = "egress"
}

# Traffic Mirror Session - Uses existing NGINX source ENI
resource "aws_ec2_traffic_mirror_session" "mirror-session" {
  description              = "Traffic mirror session from existing NGINX ENI"
  for_each                 = var.enable_mirroring ? toset(var.existing_nginx_source_enis) : []
  network_interface_id     = each.value
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.mirror-filter.id
  traffic_mirror_target_id = aws_ec2_traffic_mirror_target.mirror-target.id
  session_number           = index(var.existing_nginx_source_enis, each.value) + 1
  virtual_network_id       = var.virtual_network_id

  tags = {
    Name = "nginx-to-nlb-mirror-session"
  }
}


#################### New Ammendment #################

# Archive the Lambda function
data "archive_file" "eni_lambda_archive" {
  type        = "zip"
  source_file = "${path.module}/MultipleENIsforASG.py"
  output_path = "${path.module}/MultipleENIsforASG.zip"
}

# Lambda function
resource "aws_lambda_function" "eni_lambda" {
  filename         = data.archive_file.eni_lambda_archive.output_path
  function_name    = "vxlan-eni-lambda"
  role             = aws_iam_role.lambda_role.arn
  handler          = "MultipleENIsforASG.lambda_handler"
  runtime          = "python3.8"
  source_code_hash = data.archive_file.eni_lambda_archive.output_base64sha256

  environment {
    variables = {
      eni_sg_id = aws_security_group.vxlan_gateway.id
      subnet_mappings = jsonencode({
        (var.private_subnet_id) = var.private_subnet_id
      })
    }
  }
}

# CloudWatch Event Rule
resource "aws_cloudwatch_event_rule" "add_eni" {
  name        = "vxlan-add-eni"
  description = "Add an ENI to instances in the VXLAN ASG"

  event_pattern = jsonencode({
    source      = ["aws.autoscaling"]
    detail-type = ["EC2 Instance-launch Lifecycle Action"]
    detail = {
      AutoScalingGroupName = ["mirror-gateway-asg"]
    }
  })
}

# CloudWatch Event Target
resource "aws_cloudwatch_event_target" "cwe_target" {
  rule = aws_cloudwatch_event_rule.add_eni.name
  arn  = aws_lambda_function.eni_lambda.arn
}

# Lambda permission for CloudWatch Events
resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.eni_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.add_eni.arn
}

# Launch Template
resource "aws_launch_template" "mirror_gateway_asg" {
  name_prefix            = var.enable_xdp_migration ? "xdp-gateway-asg" : "mirror-gateway-asg"
  image_id               = var.base_ami
  instance_type          = var.ec2_instance_type
  vpc_security_group_ids = [aws_security_group.vxlan_gateway.id]
  user_data              = base64encode(var.enable_xdp_migration ? local.xdp_user_data : local.vxlan_user_data)

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name          = var.enable_xdp_migration ? "xdp-gateway-asg-instance" : "mirror-gateway-asg-instance"
      Environment   = var.environment
      Product       = var.product
      Component     = var.component
      Region        = "us-west-2"
      AppPlatform   = "cloud"
      Subcomponent  = "flow"
      InfraPlatform = "ec2"
      XDP_Enabled   = var.enable_xdp_migration
    }
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "mirror_gateway_asg" {
  depends_on          = [aws_cloudwatch_event_rule.add_eni]
  name                = "mirror-gateway-asg"
  min_size            = 2
  max_size            = var.mirroring_instance_count
  desired_capacity    = var.mirroring_instance_count
  vpc_zone_identifier = [var.private_subnet_id]
  target_group_arns   = [aws_lb_target_group.aws-mirror-tg.arn]

  launch_template {
    id      = aws_launch_template.mirror_gateway_asg.id
    version = "$Latest"
  }

  initial_lifecycle_hook {
    name                 = "vxlan-hook-add-eni"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 300
    lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"
  }

  tag {
    key                 = "Name"
    value               = "mirror-gateway-asg-instance"
    propagate_at_launch = true
  }
}