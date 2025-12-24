#!/bin/bash

# XDP VXLAN Pipeline - Performance Optimization Setup
# Configures system for 85K+ PPS processing as analyzed

set -euo pipefail

INGRESS_IF="ens4"
EGRESS_IF="ens5"

echo "🚀 Configuring XDP VXLAN Pipeline for High Performance..."

# 1. Disable GRO (Critical for jumbo frame processing)
echo "📦 Disabling GRO on ${INGRESS_IF} (prevents 2852B packet aggregation issues)..."
sudo ethtool -K ${INGRESS_IF} gro off || echo "Warning: Could not disable GRO"

# 2. Disable other offloads that can interfere with XDP
echo "⚙️  Optimizing network interface offloads..."
sudo ethtool -K ${INGRESS_IF} tso off tx-checksum-ip-generic off || true
sudo ethtool -K ${EGRESS_IF} tso off tx-checksum-ip-generic off || true

# 3. Set optimal ring buffer sizes for high PPS
echo "🔧 Optimizing ring buffer sizes for 85K+ PPS..."
sudo ethtool -G ${INGRESS_IF} rx 4096 tx 4096 2>/dev/null || echo "Warning: Could not set ring buffers"
sudo ethtool -G ${EGRESS_IF} rx 4096 tx 4096 2>/dev/null || echo "Warning: Could not set ring buffers"

# 4. Configure interrupt coalescing for low latency
echo "⚡ Configuring interrupt coalescing for sub-microsecond latency..."
sudo ethtool -C ${INGRESS_IF} rx-usecs 1 rx-frames 1 2>/dev/null || true
sudo ethtool -C ${EGRESS_IF} rx-usecs 1 rx-frames 1 2>/dev/null || true

# 5. Enable multi-queue support if available
echo "🎯 Optimizing queue configuration..."
NUM_QUEUES=$(nproc)
sudo ethtool -L ${INGRESS_IF} combined ${NUM_QUEUES} 2>/dev/null || echo "Warning: Could not set queue count"

# 6. Set CPU affinity for optimal performance
echo "🏃 Setting CPU affinity for network interrupts..."
INGRESS_IRQ=$(cat /proc/interrupts | grep ${INGRESS_IF} | head -1 | cut -d: -f1 | tr -d ' ')
if [[ -n "${INGRESS_IRQ}" ]]; then
    echo 2 | sudo tee /proc/irq/${INGRESS_IRQ}/smp_affinity > /dev/null
    echo "Set ${INGRESS_IF} IRQ ${INGRESS_IRQ} to CPU 1"
fi

# 7. Increase system limits for high PPS
echo "📈 Increasing system limits for high packet rates..."
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.rmem_default = 67108864' | sudo tee -a /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 30000' | sudo tee -a /etc/sysctl.conf
echo 'net.core.netdev_budget = 600' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 8. Set CPU governor to performance mode
echo "⚡ Setting CPU governor to performance mode..."
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null

# 9. Disable power saving features that can affect timing
echo "💡 Disabling power saving features..."
sudo ethtool -s ${INGRESS_IF} autoneg off 2>/dev/null || true

echo "✅ System optimization complete!"
echo ""
echo "📊 Current interface configuration:"
echo "--- ${INGRESS_IF} ---"
sudo ethtool -k ${INGRESS_IF} | grep -E "(generic-receive-offload|tcp-segmentation-offload)"
echo "--- ${EGRESS_IF} ---"
sudo ethtool -k ${EGRESS_IF} | grep -E "(generic-receive-offload|tcp-segmentation-offload)"

echo ""
echo "🎯 Ready for 85K+ PPS XDP processing!"
echo "💡 To verify: sudo ./src/vxlan_loader -i ${INGRESS_IF} -t ${EGRESS_IF} -v"