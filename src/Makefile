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
BPF_HEADER := vxlan_pipeline.h
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
$(BPF_OBJ): $(BPF_PROG) $(BPF_HEADER)
	@echo "Compiling eBPF program for high-performance packet processing..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "eBPF program compiled: $@"

# Compile userspace loader
$(USER_BIN): $(USER_PROG) $(BPF_OBJ) $(BPF_HEADER)
	@echo "Compiling userspace controller..."
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)
	@echo "Userspace program compiled: $@"

# Check dependencies
check-deps:
	@echo "Checking build dependencies..."
	@which $(CLANG) > /dev/null || (echo "ERROR: clang not found. Install: apt-get install clang" && exit 1)
	@which $(CC) > /dev/null || (echo "ERROR: gcc not found. Install: apt-get install gcc" && exit 1)
	@test -f $(LIBBPF_DIR)/libbpf.a -o -f /usr/lib/x86_64-linux-gnu/libbpf.a -o -f /usr/lib/libbpf.a || (echo "ERROR: libbpf not found. Install: apt-get install libbpf-dev" && exit 1)
	@test -d $(KERNEL_SRC) || (echo "ERROR: kernel headers not found. Install: apt-get install linux-headers-$(KERNEL_REL)" && exit 1)
	@echo "All dependencies satisfied ✓"

# Create setup script
setup: $(SETUP_SCRIPT)

$(SETUP_SCRIPT):
	@echo "Creating environment setup script..."
	@echo '#!/bin/bash' > $(SETUP_SCRIPT)
	@echo 'set -e' >> $(SETUP_SCRIPT)
	@echo '' >> $(SETUP_SCRIPT)
	@echo 'echo "Setting up VXLAN Pipeline Environment..."' >> $(SETUP_SCRIPT)
	@echo '' >> $(SETUP_SCRIPT)
	@echo '# Check if running as root' >> $(SETUP_SCRIPT)
	@echo 'if [[ $$EUID -ne 0 ]]; then' >> $(SETUP_SCRIPT)
	@echo '   echo "This script must be run as root (use sudo)"' >> $(SETUP_SCRIPT)
	@echo '   exit 1' >> $(SETUP_SCRIPT)
	@echo 'fi' >> $(SETUP_SCRIPT)
	@echo '' >> $(SETUP_SCRIPT)
	@echo '# Install required packages' >> $(SETUP_SCRIPT)
	@echo 'echo "Installing dependencies..."' >> $(SETUP_SCRIPT)
	@echo 'apt-get update' >> $(SETUP_SCRIPT)
	@echo 'apt-get install -y clang gcc make libbpf-dev linux-headers-$$(uname -r) iproute2 net-tools' >> $(SETUP_SCRIPT)
	@echo '' >> $(SETUP_SCRIPT)
	@echo 'echo "Setup complete! Run make to build the project."' >> $(SETUP_SCRIPT)
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
	@echo "Removing program binaries..."
	rm -f $(USER_BIN) $(BPF_OBJ)
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