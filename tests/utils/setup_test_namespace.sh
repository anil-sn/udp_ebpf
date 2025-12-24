#!/bin/bash
# Setup network namespace for proper XDP testing
# This creates an isolated environment to simulate external traffic

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

NAMESPACE="xdp-test"
VETH_HOST="veth-host"
VETH_NS="veth-ns"
HOST_IP="192.168.100.1"
NS_IP="192.168.100.2"

echo -e "${BLUE}🔧 Setting up XDP test environment${NC}"

# Check if running as root
if [ $EUID -ne 0 ]; then
    echo -e "${RED}❌ Must run as root${NC}"
    exit 1
fi

# Cleanup existing setup
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up existing setup${NC}"
    ip netns del $NAMESPACE 2>/dev/null || true
    ip link del $VETH_HOST 2>/dev/null || true
}

# Setup function
setup() {
    echo -e "${BLUE}📋 Step 1: Creating network namespace${NC}"
    ip netns add $NAMESPACE

    echo -e "${BLUE}📋 Step 2: Creating veth pair${NC}"
    ip link add $VETH_HOST type veth peer name $VETH_NS

    echo -e "${BLUE}📋 Step 3: Moving veth to namespace${NC}"
    ip link set $VETH_NS netns $NAMESPACE

    echo -e "${BLUE}📋 Step 4: Configuring host side${NC}"
    ip addr add ${HOST_IP}/24 dev $VETH_HOST
    ip link set $VETH_HOST up

    echo -e "${BLUE}📋 Step 5: Configuring namespace side${NC}"
    ip netns exec $NAMESPACE ip addr add ${NS_IP}/24 dev $VETH_NS
    ip netns exec $NAMESPACE ip link set $VETH_NS up
    ip netns exec $NAMESPACE ip link set lo up

    echo -e "${BLUE}📋 Step 6: Adding routes${NC}"
    ip route add ${NS_IP}/32 dev $VETH_HOST 2>/dev/null || true
    ip netns exec $NAMESPACE ip route add ${HOST_IP}/32 dev $VETH_NS 2>/dev/null || true

    echo -e "${GREEN}✅ Test environment ready${NC}"
    echo "Host interface: $VETH_HOST (IP: $HOST_IP)"
    echo "Namespace: $NAMESPACE (IP: $NS_IP)"
    echo ""
    echo -e "${YELLOW}💡 Usage:${NC}"
    echo "1. Attach XDP to: $VETH_HOST"
    echo "2. Send traffic from namespace to: $HOST_IP:4789"
    echo "3. Command: ip netns exec $NAMESPACE <traffic_command>"
}

case "${1:-setup}" in
    setup)
        cleanup
        setup
        ;;
    cleanup)
        cleanup
        echo -e "${GREEN}✅ Cleanup complete${NC}"
        ;;
    status)
        echo -e "${BLUE}📊 Current setup:${NC}"
        ip netns list | grep $NAMESPACE && echo "Namespace: ✅ $NAMESPACE" || echo "Namespace: ❌ Missing"
        ip link show $VETH_HOST 2>/dev/null && echo "Host veth: ✅ $VETH_HOST" || echo "Host veth: ❌ Missing"
        ip netns exec $NAMESPACE ip link show $VETH_NS 2>/dev/null && echo "NS veth: ✅ $VETH_NS" || echo "NS veth: ❌ Missing"
        ;;
    *)
        echo "Usage: $0 {setup|cleanup|status}"
        exit 1
        ;;
esac