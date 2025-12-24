#!/bin/bash
# VXLAN Pipeline Configuration Validator

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}VXLAN Pipeline Configuration Validator${NC}"
echo "========================================"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo -e "${RED}ERROR: .env file not found${NC}"
    echo "Please create a .env file using the template or run the setup."
    exit 1
fi

# Source the configuration
source .env

echo -e "${GREEN}✓ Configuration file found${NC}"
echo ""

# Validate network interfaces
echo -e "${BLUE}Network Interface Validation:${NC}"
if ip link show "$INTERFACE" >/dev/null 2>&1; then
    echo -e "  Primary Interface ($INTERFACE): ${GREEN}✓ Found${NC}"
else
    echo -e "  Primary Interface ($INTERFACE): ${RED}✗ Not Found${NC}"
fi

if [ -n "$TARGET_INTERFACE" ]; then
    if ip link show "$TARGET_INTERFACE" >/dev/null 2>&1; then
        echo -e "  Target Interface ($TARGET_INTERFACE): ${GREEN}✓ Found${NC}"
    else
        echo -e "  Target Interface ($TARGET_INTERFACE): ${RED}✗ Not Found${NC}"
    fi
fi

# Validate IP address format
echo -e "${BLUE}NAT Configuration Validation:${NC}"
if [[ $NAT_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "  NAT IP ($NAT_IP): ${GREEN}✓ Valid Format${NC}"
else
    echo -e "  NAT IP ($NAT_IP): ${RED}✗ Invalid Format${NC}"
fi

# Validate port ranges
if [ "$NAT_PORT" -ge 1 ] && [ "$NAT_PORT" -le 65535 ]; then
    echo -e "  NAT Port ($NAT_PORT): ${GREEN}✓ Valid Range${NC}"
else
    echo -e "  NAT Port ($NAT_PORT): ${RED}✗ Invalid Range (1-65535)${NC}"
fi

if [ "$SOURCE_PORT" -ge 1 ] && [ "$SOURCE_PORT" -le 65535 ]; then
    echo -e "  Source Port ($SOURCE_PORT): ${GREEN}✓ Valid Range${NC}"
else
    echo -e "  Source Port ($SOURCE_PORT): ${RED}✗ Invalid Range (1-65535)${NC}"
fi

# Check required binaries
echo -e "${BLUE}Binary Dependencies:${NC}"
for binary in clang gcc make; do
    if command -v "$binary" >/dev/null 2>&1; then
        echo -e "  $binary: ${GREEN}✓ Available${NC}"
    else
        echo -e "  $binary: ${RED}✗ Missing${NC}"
    fi
done

# Check if vxlan_loader exists in src directory
if [ -f "../src/vxlan_loader" ]; then
    echo -e "  vxlan_loader: ${GREEN}✓ Found${NC}"
else
    echo -e "  vxlan_loader: ${YELLOW}! Not built (run 'make' in src directory)${NC}"
fi

echo ""
echo -e "${BLUE}Configuration Summary:${NC}"
echo "  Interface: $INTERFACE → $TARGET_INTERFACE"
echo "  NAT Rule: port $SOURCE_PORT → $NAT_IP:$NAT_PORT"
echo "  Stats Interval: ${STATS_INTERVAL}s"
echo "  Log File: $LOG_FILE"
echo "  Target PPS: $TARGET_PPS"

echo ""
echo -e "${GREEN}Validation complete!${NC}"