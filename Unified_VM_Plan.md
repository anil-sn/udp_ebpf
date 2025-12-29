This is the correct approach for Infrastructure-as-Code (IaC). We will move the entire **Infrastructure Setup** (IPSec configuration, Network Interfaces, Routing, and `.env` generation) into Terraform's `user_data`.

When the VM boots, the tunnel will establish automatically, and the `tap0` interface will be ready. The XDP application simply needs to start.

### 1. Terraform Configuration (`main.tf`)

This configuration iterates over your `vm_configs` map, creating instances and injecting the specific configuration for each VM into the startup script.

```hcl
variable "vm_configs" {
  type = map(object({
    name                    = string
    aws_leftid              = string
    gcp_right               = string # GCP Public IP
    gcp_rightid             = string
    gcp_rightsubnet         = string # The Target Subnet (100.68.x.x/20)
    gcp_ipsec_vm_private_ip = string # The Target Private IP for XDP NAT
  }))
}

variable "pre_shared_key" { type = string }
variable "aws_leftsubnet" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_id" { type = string }
variable "base_ami" { type = string }
variable "ec2_instance_type" { type = string }

resource "aws_security_group" "unified_sg" {
  name        = "unified-xdp-ipsec-sg"
  description = "Allow VXLAN and IPSec traffic"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 4789
    to_port     = 4789
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"] # Limit this to your source ranges in prod
    description = "VXLAN Ingress"
  }

  ingress {
    from_port   = 500
    to_port     = 500
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "IKE"
  }

  ingress {
    from_port   = 4500
    to_port     = 4500
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "IPSec NAT-T"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "unified_vm" {
  for_each = var.vm_configs

  ami           = var.base_ami
  instance_type = var.ec2_instance_type
  subnet_id     = var.private_subnet_id
  
  # Ensure Source/Dest check is disabled for routing
  source_dest_check = false
  
  vpc_security_group_ids = [aws_security_group.unified_sg.id]

  tags = {
    Name = each.value.name
  }

  # Inject configuration via template
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    # IPSec Config
    AWS_LEFTID      = each.value.aws_leftid
    GCP_RIGHT_IP    = split("/", each.value.gcp_right)[0] # Strip CIDR if present
    GCP_RIGHTID     = each.value.gcp_rightid
    GCP_SUBNET      = each.value.gcp_rightsubnet
    AWS_LEFTSUBNET  = var.aws_leftsubnet
    PSK             = var.pre_shared_key
    
    # XDP Config
    GCP_TARGET_IP   = each.value.gcp_ipsec_vm_private_ip
  })
}
```

### 2. User Data Template (`user_data.sh.tpl`)

This script runs on first boot. It sets up the **Unified Architecture**: `tap0` creation, `ipsec0` creation, Routing, StrongSwan config, and generates the `.env` file for your application.

```bash
#!/bin/bash
set -e

# --- 1. SYSTEM SETUP ---
apt-get update
apt-get install -y strongswan-swanctl charon-systemd libcharon-extra-plugins \
    apt-transport-https ca-certificates gnupg curl build-essential \
    clang llvm libbpf-dev linux-headers-$(uname -r) iproute2 net-tools

# Enable Forwarding
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# --- 2. NETWORK INTERFACE SETUP (Unified Architecture) ---

# A. Create IPSec XFRM Interface
ip link add ipsec0 type xfrm if_id 10
ip link set ipsec0 up
ip link set ipsec0 mtu 1360

# B. Create TAP Interface (Input for Kernel from XDP)
ip tuntap add dev tap0 mode tap
# Assign dummy IP so kernel treats it as L3 valid
ip addr add 169.254.1.1/30 dev tap0
ip link set tap0 up
ip link set tap0 mtu 1360

# --- 3. ROUTING CONFIGURATION ---
# CRITICAL: Traffic for GCP Subnet injected into tap0 must go to ipsec0
# This completes the "loopback" from User Space -> Kernel -> IPSec
ip route add ${GCP_SUBNET} dev ipsec0

# --- 4. STRONGSWAN CONFIGURATION ---
mkdir -p /etc/swanctl
cat <<EOF > /etc/swanctl/swanctl.conf
connections {
  aws-to-gcp {
    version = 2
    remote_addrs = ${GCP_RIGHT_IP}
    dpd_delay = 30s
    dpd_timeout = 120s
    rekey_time = 1h
    encap = yes
    
    local {
      auth = psk
      id = ${AWS_LEFTID}
    }
    remote {
      auth = psk
      id = ${GCP_RIGHTID}
    }
    children {
      aws-to-gcp {
        mode = tunnel
        # Allow 0.0.0.0/0 local_ts to accept traffic from tap0/anywhere
        local_ts = 0.0.0.0/0
        remote_ts = ${GCP_SUBNET}
        dpd_action = restart
        esp_proposals = aes256gcm16-sha384
        rekey_time = 8h
        start_action = start
        if_id_in = 10
        if_id_out = 10
      }
    }
    proposals = aes256-sha256-modp2048
  }
}
secrets {
  ike-aws-to-gcp {
    id = ${AWS_LEFTID}
    secret = "${PSK}"
  }
}
EOF

# Start IPSec
systemctl restart strongswan

# --- 5. XDP APPLICATION CONFIGURATION ---
# Generate the .env file for the application to read at runtime.
# The application ONLY needs to know where to NAT the packet and where to inject it.
mkdir -p /opt/vxlan-pipeline
cat <<EOF > /opt/vxlan-pipeline/.env
# Generated by Terraform User Data
INTERFACE=ens5
TARGET_INTERFACE=tap0

# XDP NAT Target
NAT_IP=${GCP_TARGET_IP}
NAT_PORT=8081
SOURCE_PORT=31765

# Performance
STATS_INTERVAL=5
TARGET_PPS=85000
EOF

# --- 6. PERSISTENCE (Optional) ---
# Ensure tap0 and routes persist on reboot
cat <<EOF > /etc/network/if-pre-up.d/xdp-tap
#!/bin/bash
ip link show tap0 >/dev/null 2>&1 || ip tuntap add dev tap0 mode tap
ip addr add 169.254.1.1/30 dev tap0 2>/dev/null
ip link set tap0 up
ip link set tap0 mtu 1360
ip link add ipsec0 type xfrm if_id 10 2>/dev/null
ip link set ipsec0 up
ip route add ${GCP_SUBNET} dev ipsec0 2>/dev/null
EOF
chmod +x /etc/network/if-pre-up.d/xdp-tap

echo "VM Provisioning Complete. IPSec UP. Network Ready."
```

### 3. Application Workflow (Runtime)

Since Terraform has handled the heavy lifting, your runtime workflow becomes incredibly simple.

**1. Deployment:**
Terraform runs. VM boots.
*   StrongSwan starts and establishes tunnel with GCP.
*   `tap0` is created.
*   Route `100.68.16.0/20 -> ipsec0` is added.
*   `.env` file is created at `/opt/vxlan-pipeline/.env`.

**2. Application Start:**
You simply deploy your code to `/opt/vxlan-pipeline` and run:

```bash
# Code assumes setup_unified.sh logic is already done by Terraform
cd /opt/vxlan-pipeline
sudo ./xdp.sh start
```

### 4. Why this is better
1.  **Immutability:** No manual `setup_unified.sh` execution. If you terminate the instance, the new one comes up with the exact same networking state.
2.  **Security:** PSKs and IPs are managed in Terraform state, not scattered in shell scripts on disk (except the generated config files).
3.  **Simplicity:** The XDP application logic is strictly "Receive VXLAN -> Decap -> Write to TAP". It doesn't need to know *how* the packet gets to GCP, only that `tap0` is the gateway.

### 5. Verification Command (After TF Apply)

SSH into the new instance and run:

```bash
# 1. Check if Tunnel Interface exists
ip link show ipsec0

# 2. Check if Route exists (Crucial for Unified VM)
# Should return: 100.68.16.35 dev ipsec0 ...
ip route get 100.68.16.35

# 3. Check if tap0 exists
ip link show tap0

# 4. Check if .env was generated
cat /opt/vxlan-pipeline/.env
```