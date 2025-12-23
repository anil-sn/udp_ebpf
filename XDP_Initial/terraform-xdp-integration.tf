# XDP-enabled user data template for Terraform
# This replaces the legacy netfilter implementation with high-performance XDP

variable "enable_xdp_migration" {
  description = "Enable XDP migration (true) or keep legacy netfilter (false)"
  type        = bool
  default     = true
}

# XDP user data template
locals {
  xdp_user_data = <<-EOS
#!/bin/bash
set -e

# Configure network interfaces (preserve existing logic)
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

# Network configuration variables (same as before)
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
    
    # Network setup (preserve existing bridge configuration)
    ip link add br0 type bridge
    ip link set br0 address $SECONDARY_ENI_MAC
    ip link add vxlan1 type vxlan id 1 dstport 4789
    ip link set vxlan1 master br0
    ip link set $SECONDARY_ENI master br0
    ip link set up dev vxlan1
    ip link set up dev ens6
    ip link set up dev br0
    
    # Get IP for secondary interface
    dhclient br0
    SECONDARY_ENI_IP=$(ip addr sh dev br0 | awk '/inet /{print $2}')

    # iptables rules (preserve existing routing logic)
    iptables -t nat -A PREROUTING -p udp -m udp --dport 31765 -j DNAT --to-destination $${AWS_IPSEC_VM_IP}:$${AWS_IPSEC_VM_PORT}
    ebtables -t nat -A PREROUTING -p IPv4 -i vxlan1 --ip-proto udp --ip-dport 31765 -j dnat --to-dst $SECONDARY_ENI_MAC --dnat-target ACCEPT

    # Deploy XDP codebase
    cd /opt
    mkdir -p xdp-processor
    cd xdp-processor

    # Deploy XDP source files (base64 encoded for reliability)
    cat << 'XDPEOF' | base64 -d > udp_df_modifier.bpf.c
${base64encode(file("${path.module}/udp_df_modifier.bpf.c"))}
XDPEOF

    cat << 'XDPEOF' | base64 -d > udp_df_modifier_loader.c  
${base64encode(file("${path.module}/udp_df_modifier_loader.c"))}
XDPEOF

    cat << 'XDPEOF' | base64 -d > Makefile
${base64encode(file("${path.module}/Makefile"))}
XDPEOF

    cat << 'XDPEOF' | base64 -d > deploy_xdp.sh
${base64encode(file("${path.module}/deploy_xdp.sh"))}
XDPEOF

    cat << 'XDPEOF' | base64 -d > setup_xdp.sh
${base64encode(file("${path.module}/setup_xdp.sh"))}
XDPEOF

    chmod +x deploy_xdp.sh setup_xdp.sh

    # Build XDP programs
    make production

    # Install and start XDP service (replaces netfilter NFQUEUE)
    ./deploy_xdp.sh install
    ./deploy_xdp.sh attach br0

    # Network route configuration (preserve existing logic)  
    ip link set br0 mtu 1400
    ip route add $GCP_PREFIX via $DEFAULT_GW dev br0
    ip route del default via $DEFAULT_GW dev br0

    # Clean up old netfilter components if they exist
    systemctl disable modify_udp.service 2>/dev/null || true
    systemctl stop modify_udp.service 2>/dev/null || true

    echo "XDP UDP DF modifier deployed successfully on br0"
fi
EOF

chmod 755 $DESTPATH
systemctl restart networkd-dispatcher
EOS

  # Legacy netfilter user data (for rollback capability)  
  legacy_user_data = <<-EOS
#!/bin/bash
# ... existing netfilter implementation ...
${local.vxlan_user_data}
EOS
}

# Use conditional user_data based on migration flag
resource "aws_launch_template" "mirror_gateway_asg" {
  name_prefix            = var.enable_xdp_migration ? "xdp-gateway-" : "mirror-gateway-"
  image_id               = var.base_ami
  instance_type          = var.ec2_instance_type
  vpc_security_group_ids = [aws_security_group.vxlan_gateway.id]
  user_data              = var.enable_xdp_migration ? base64encode(local.xdp_user_data) : base64encode(local.legacy_user_data)

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name          = var.enable_xdp_migration ? "xdp-gateway-instance" : "mirror-gateway-instance"
      Environment   = var.environment
      Product       = var.product  
      Component     = var.component
      XDP_Enabled   = var.enable_xdp_migration
    }
  }
}