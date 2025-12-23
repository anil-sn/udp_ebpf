# Safe Production Makefile for UDP DF Modifier using eBPF/XDP
#
# This Makefile builds both the eBPF kernel program and userspace loader
# with balanced optimizations suitable for production environments.

# Compiler and tool configuration
CC = gcc
CLANG = clang
LLVM_STRIP = llvm-strip

# Safe production compilation flags
CFLAGS = -O2 -Wall -Wextra -std=gnu99 -g
CFLAGS += -fstack-protector-strong    # Stack protection
CFLAGS += -D_FORTIFY_SOURCE=2         # Buffer overflow detection
CFLAGS += -Werror=format-security     # Format string security

# eBPF-specific flags (conservative settings)
BPF_CFLAGS = -O2 -g -Wall -Wextra
BPF_CFLAGS += -target bpf
BPF_CFLAGS += -D__KERNEL__
BPF_CFLAGS += -Wno-unused-value -Wno-pointer-sign
BPF_CFLAGS += -Wno-compare-distinct-pointer-types
BPF_CFLAGS += -Wno-gnu-variable-sized-type-not-at-end
BPF_CFLAGS += -Wno-address-of-packed-member -Wno-tautological-compare
BPF_CFLAGS += -Wno-unknown-warning-option

# Library dependencies
LIBS = -lbpf -lelf -lz

# Source and target files
BPF_SOURCE = udp_df_modifier.bpf.c
BPF_OBJECT = udp_df_modifier.bpf.o
LOADER_SOURCE = udp_df_modifier_loader.c
LOADER_TARGET = udp_df_modifier_xdp

# Include paths
INCLUDES = -I/usr/include

# Default target - build both programs
all: $(BPF_OBJECT) $(LOADER_TARGET)
	@echo "Build completed successfully"
	@echo "Next steps:"
	@echo "  sudo ./setup_xdp.sh           # Install dependencies"
	@echo "  sudo ./deploy_xdp.sh install  # Install to system"
	@echo "  sudo ./deploy_xdp.sh attach <interface>  # Attach XDP program"

# Build eBPF kernel program
$(BPF_OBJECT): $(BPF_SOURCE)
	@echo "Building eBPF program: $(BPF_SOURCE) -> $(BPF_OBJECT)"
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

# Build userspace loader
$(LOADER_TARGET): $(LOADER_SOURCE) $(BPF_OBJECT)
	@echo "Building userspace loader: $(LOADER_SOURCE) -> $(LOADER_TARGET)"
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(LOADER_SOURCE) $(LIBS)

# Verify eBPF program (requires bpftool)
verify: $(BPF_OBJECT)
	@echo "Verifying eBPF program..."
	@if command -v bpftool >/dev/null 2>&1; then \
		bpftool prog load $(BPF_OBJECT) /sys/fs/bpf/test_udp_df_modifier 2>/dev/null && \
		echo "eBPF program verification successful" && \
		rm -f /sys/fs/bpf/test_udp_df_modifier || \
		(echo "eBPF program verification failed" && exit 1); \
	else \
		echo "bpftool not available, skipping verification"; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BPF_OBJECT) $(LOADER_TARGET)

# Install to system (requires root)
install: all
	@echo "Installing to system (requires sudo)..."
	sudo ./deploy_xdp_safe.sh install

# Development helpers
dev-setup:
	@echo "Setting up development environment..."
	sudo ./setup_xdp_safe.sh

# Quick test build (minimal flags for faster iteration)
quick: BPF_CFLAGS = -O0 -g -target bpf -D__KERNEL__
quick: CFLAGS = -O0 -g -Wall
quick: $(BPF_OBJECT) $(LOADER_TARGET)
	@echo "Quick development build completed"

# Production build with full optimizations
production: BPF_CFLAGS += -DNDEBUG
production: CFLAGS += -O3 -DNDEBUG
production: $(BPF_OBJECT) $(LOADER_TARGET)
	@echo "Production build completed"

# Show build information
info:
	@echo "Build Configuration:"
	@echo "  CC: $(CC)"
	@echo "  CLANG: $(CLANG)"
	@echo "  CFLAGS: $(CFLAGS)"
	@echo "  BPF_CFLAGS: $(BPF_CFLAGS)"
	@echo "  LIBS: $(LIBS)"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build both eBPF program and loader"
	@echo "  verify     - Verify eBPF program correctness"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install to system (requires sudo)"
	@echo "  dev-setup  - Setup development environment"
	@echo "  quick      - Fast development build"
	@echo "  production - Optimized production build"

# Help target
help: info

# Declare phony targets
.PHONY: all verify clean install dev-setup quick production info help