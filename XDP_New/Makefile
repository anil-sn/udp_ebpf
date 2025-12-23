# High-Performance VXLAN Pipeline Makefile
# Optimized for 85K+ packets/second processing

# Compiler and flags
CLANG := clang
LLC := llc
CC := gcc

# Kernel headers and include paths
KERNEL_REL := $(shell uname -r)
KERNEL_SRC := /lib/modules/$(KERNEL_REL)/build
LIBBPF_DIR := /usr/lib/x86_64-linux-gnu

# Compiler flags for eBPF
BPF_CFLAGS := -O2 -target bpf -g \
              -I$(KERNEL_SRC)/arch/x86/include \
              -I$(KERNEL_SRC)/arch/x86/include/generated \
              -I$(KERNEL_SRC)/include \
              -I$(KERNEL_SRC)/arch/x86/include/uapi \
              -I$(KERNEL_SRC)/arch/x86/include/generated/uapi \
              -I$(KERNEL_SRC)/include/uapi \
              -I$(KERNEL_SRC)/include/generated/uapi \
              -I/usr/include/x86_64-linux-gnu \
              -Wno-unused-value -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -Wno-gnu-variable-sized-type-not-at-end \
              -Wno-address-of-packed-member -Wno-tautological-compare \
              -Wno-unknown-warning-option

# Compiler flags for userspace
USER_CFLAGS := -Wall -Wextra -O2 -g \
               -I$(LIBBPF_DIR)/include \
               -std=c99

# Linker flags
USER_LDFLAGS := -L$(LIBBPF_DIR)/lib -lbpf -lelf -lz

# Target files
BPF_PROG := vxlan_pipeline.bpf.c
BPF_OBJ := vxlan_pipeline.bpf.o
USER_PROG := vxlan_loader.c
USER_BIN := vxlan_loader

# Additional utilities
SETUP_SCRIPT := setup_environment.sh
SERVICE_FILE := vxlan-pipeline.service
CONFIG_FILE := vxlan_config.conf

.PHONY: all clean install uninstall check-deps setup test

# Default target
all: check-deps $(BPF_OBJ) $(USER_BIN)

# Compile eBPF program
$(BPF_OBJ): $(BPF_PROG)
	@echo "Compiling eBPF program for high-performance packet processing..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "eBPF program compiled: $@"

# Compile userspace loader
$(USER_BIN): $(USER_PROG) $(BPF_OBJ)
	@echo "Compiling userspace controller..."
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)
	@echo "Userspace program compiled: $@"

# Check dependencies
check-deps:
	@echo "Checking build dependencies..."
	@which $(CLANG) > /dev/null || (echo "ERROR: clang not found. Install: apt-get install clang" && exit 1)
	@which $(CC) > /dev/null || (echo "ERROR: gcc not found. Install: apt-get install gcc" && exit 1)
	@test -f $(LIBBPF_DIR)/lib/libbpf.a || (echo "ERROR: libbpf not found. Install: apt-get install libbpf-dev" && exit 1)
	@test -d $(KERNEL_SRC) || (echo "ERROR: kernel headers not found. Install: apt-get install linux-headers-$(KERNEL_REL)" && exit 1)
	@echo "All dependencies satisfied ✓"

# Create setup script
setup: $(SETUP_SCRIPT)

$(SETUP_SCRIPT):
	@echo "Creating environment setup script..."
	@cat > $(SETUP_SCRIPT) << 'EOF'
#!/bin/bash
set -e

echo "Setting up VXLAN Pipeline Environment..."

# Check if running as root
if [[ $$EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

# Install required packages
echo "Installing dependencies..."
apt-get update
apt-get install -y \
    clang \
    gcc \
    make \
    libbpf-dev \
    linux-headers-$$(uname -r) \
    iproute2 \
    net-tools

# Enable IP forwarding
echo "Configuring system for packet forwarding..."
echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
sysctl -p

# Increase socket buffer sizes for high-traffic workloads
echo "Optimizing network buffers for 85K+ pps..."
echo 'net.core.rmem_default = 262144' >> /etc/sysctl.conf
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_default = 262144' >> /etc/sysctl.conf  
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf
sysctl -p

# Set CPU governor to performance for consistent latency
echo "Setting CPU governor to performance mode..."
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [ -f "$$cpu" ] && echo performance > "$$cpu"
done

# Create systemd service
echo "Creating systemd service..."
cat > /etc/systemd/system/vxlan-pipeline.service << 'EOD'
[Unit]
Description=High-Performance VXLAN Pipeline XDP Service
After=network.target
Requires=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vxlan-pipeline
ExecStart=/opt/vxlan-pipeline/vxlan_loader -i ens5 -t ens6 -a 127.0.0.1 -p 8080 -s 31765
Restart=always
RestartSec=5

# Performance optimizations
Nice=-10
IOSchedulingClass=1
IOSchedulingPriority=4

[Install]
WantedBy=multi-user.target
EOD

systemctl daemon-reload

echo "Setup complete! Next steps:"
echo "1. Build the project: make"
echo "2. Test manually: sudo ./vxlan_loader --help"
echo "3. Install service: sudo make install"
echo "4. Start service: sudo systemctl start vxlan-pipeline"
EOF
	chmod +x $(SETUP_SCRIPT)
	@echo "Setup script created: $(SETUP_SCRIPT)"

# Install to system
install: all $(SETUP_SCRIPT)
	@echo "Installing VXLAN Pipeline to system..."
	mkdir -p /opt/vxlan-pipeline
	cp $(BPF_OBJ) $(USER_BIN) /opt/vxlan-pipeline/
	cp $(SETUP_SCRIPT) /opt/vxlan-pipeline/
	@echo "Installation complete. Run '/opt/vxlan-pipeline/$(SETUP_SCRIPT)' to configure system."

# Uninstall from system  
uninstall:
	@echo "Uninstalling VXLAN Pipeline..."
	systemctl stop vxlan-pipeline || true
	systemctl disable vxlan-pipeline || true
	rm -f /etc/systemd/system/vxlan-pipeline.service
	rm -rf /opt/vxlan-pipeline
	systemctl daemon-reload
	@echo "Uninstallation complete."

# Test program compilation and basic functionality
test: all
	@echo "Running basic tests..."
	@echo "✓ eBPF program compiles successfully"
	@echo "✓ Userspace program compiles successfully"
	@./$(USER_BIN) --help > /dev/null && echo "✓ Userspace program shows help" || echo "✗ Help test failed"
	@echo "Manual testing required:"
	@echo "  1. sudo ./$(USER_BIN) -i <interface> --help"
	@echo "  2. Monitor with: sudo ./$(USER_BIN) -i ens5 -v"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BPF_OBJ) $(USER_BIN)
	rm -f $(SETUP_SCRIPT)
	rm -f *.o *.ll
	@echo "Clean complete."

# Show build information
info:
	@echo "=== VXLAN Pipeline Build Configuration ==="
	@echo "eBPF Program: $(BPF_PROG) -> $(BPF_OBJ)"
	@echo "User Program: $(USER_PROG) -> $(USER_BIN)"
	@echo "Clang: $(shell which $(CLANG))"
	@echo "GCC: $(shell which $(CC))"
	@echo "Kernel: $(KERNEL_REL)"
	@echo "Kernel Source: $(KERNEL_SRC)"
	@echo "LibBPF: $(LIBBPF_DIR)"
	@echo "=========================================="

# Help target
help:
	@echo "VXLAN Pipeline Makefile - High-Performance Packet Processing"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build eBPF program and userspace loader (default)"
	@echo "  setup      - Create system setup script"
	@echo "  install    - Install to /opt/vxlan-pipeline"
	@echo "  uninstall  - Remove from system"
	@echo "  test       - Run basic functionality tests"
	@echo "  clean      - Remove build artifacts"
	@echo "  check-deps - Check build dependencies"
	@echo "  info       - Show build configuration"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Usage for 85K+ pps workload:"
	@echo "  make && sudo ./vxlan_loader -i ens5 -t ens6 -v"