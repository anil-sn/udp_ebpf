# XDP VXLAN Pipeline - Core Source Code

This directory contains the core source code for the XDP VXLAN pipeline.

## Files

- **vxlan_pipeline.bpf.c** - XDP program (kernel space) that processes VXLAN packets
- **vxlan_loader.c** - Userspace control plane for loading and managing the XDP program  
- **vxlan_pipeline.h** - Shared configuration constants and definitions
- **Makefile** - Build system for compiling the XDP program and userspace components

## Building

```bash
# Clean and build everything
make clean && make all

# Build individual components
make vxlan_pipeline.bpf.o    # Compile eBPF program
make vxlan_loader            # Compile userspace loader

# Clean build artifacts
make clean
```

## Configuration

Edit `vxlan_pipeline.h` to modify:
- NAT IP address and port mappings
- VXLAN configuration (VNI, port numbers)
- Performance tuning parameters
- Debug settings

## Usage

After building, the `vxlan_loader` binary can be executed from the parent directory:

```bash
# From ebpf/ directory
sudo ./src/vxlan_loader -i eth0 -t eth1 -v
```

Or use the convenience scripts:

```bash
# From ebpf/ directory  
./xdp.sh start
```

## Dependencies

- **clang** (>= 10.0) - For eBPF compilation
- **libbpf-dev** - eBPF userspace library
- **linux-headers** - Kernel headers for your kernel version
- **gcc** - For userspace program compilation

Install on Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y clang libbpf-dev linux-headers-$(uname -r) gcc make
```

## Performance Notes

The code is optimized for:
- **Target**: 85,000+ packets/second sustained throughput
- **Latency**: Sub-microsecond per-packet processing  
- **Memory**: Minimal memory allocation in fast path
- **CPU**: Efficient packet processing with minimal CPU overhead

For maximum performance, ensure:
- CPU frequency scaling is set to performance mode
- IOMMU is disabled if not needed
- Network interface interrupts are properly distributed
- System is not under heavy load during testing