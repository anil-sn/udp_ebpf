#!/bin/bash
# Comprehensive packet flow debugging using netfilter hooks
# Usage: sudo ./debug_packet_flow.sh start|stop|show

set -euo pipefail

# Load .env configuration if available
if [[ -f ".env" ]]; then
    echo "📁 Loading configuration from .env file..."
    # Source .env file, filtering out comments and empty lines
    set -a  # automatically export variables
    source <(grep -v '^#' .env | grep -v '^$')
    set +a
else
    echo "⚠️  No .env file found, using defaults"
fi

# Configuration - modify these as needed or use .env file
SRC_IP="${SRC_IP:-172.30.82.13}"
DST_IP="${NAT_IP:-172.30.82.95}"           # Use NAT_IP from .env
DST_PORT="${SOURCE_PORT:-31765}"            # Use SOURCE_PORT from .env (the port VXLAN pipeline matches)
NAT_TARGET_PORT="${NAT_PORT:-8081}"         # The port it gets translated TO
INTERFACE="${TARGET_INTERFACE:-ens6}"       # Use TARGET_INTERFACE from .env

validate_environment() {
    # Check if running as root (for iptables operations)
    if [[ $EUID -ne 0 ]] && [[ "$1" != "show" ]] && [[ "$1" != "route" ]]; then
        echo "❌ This operation requires root privileges (use sudo)"
        exit 1
    fi
    
    # Validate IP addresses
    if ! [[ "$SRC_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "❌ Invalid source IP: $SRC_IP"
        exit 1
    fi
    
    if ! [[ "$DST_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "❌ Invalid destination IP: $DST_IP"
        exit 1
    fi
    
    # Check if interface exists (for test command)
    if [[ "$1" == "test" ]] && [[ ! -d "/sys/class/net/$INTERFACE" ]]; then
        echo "❌ Interface $INTERFACE not found. Available interfaces:"
        ls /sys/class/net/ | grep -v "^lo$" | head -5
        exit 1
    fi
}

setup_tracing() {
    validate_environment "start"
    echo "🔍 Setting up packet flow tracing for VXLAN pipeline:"
    echo "   📥 Incoming: ANY → $DST_IP:$DST_PORT (matches SOURCE_PORT)" 
    echo "   📤 Expected output: ANY → $DST_IP:$NAT_TARGET_PORT (NAT_PORT)"
    
    # Clear existing rules
    cleanup_tracing 2>/dev/null || true
    
    # === INCOMING PACKET TRACING (to SOURCE_PORT) ===
    # PREROUTING - Track incoming packets to SOURCE_PORT
    iptables -t raw -I PREROUTING -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "PRE_ROUTING_IN: " --log-level 6
    
    # FORWARD - Track forwarded packets to SOURCE_PORT
    iptables -t filter -I FORWARD -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "FORWARD_IN: " --log-level 6
        
    # INPUT - Track packets destined for local delivery to SOURCE_PORT
    iptables -t filter -I INPUT -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "INPUT_IN: " --log-level 6
    
    # === OUTGOING PACKET TRACING (to NAT_PORT) ===
    # OUTPUT - Track locally generated packets to NAT_PORT
    iptables -t filter -I OUTPUT -d $DST_IP -p udp --dport $NAT_TARGET_PORT \
        -j LOG --log-prefix "OUTPUT_NAT: " --log-level 6
    
    # POSTROUTING - Track outgoing packets to NAT_PORT
    iptables -t nat -I POSTROUTING -d $DST_IP -p udp --dport $NAT_TARGET_PORT \
        -j LOG --log-prefix "POST_ROUTING_NAT: " --log-level 6
    
    # FORWARD - Track forwarded packets to NAT_PORT  
    iptables -t filter -I FORWARD -d $DST_IP -p udp --dport $NAT_TARGET_PORT \
        -j LOG --log-prefix "FORWARD_NAT: " --log-level 6
        
    # === BIDIRECTIONAL TRACING ===
    # Track return traffic from NAT_PORT
    iptables -t raw -I PREROUTING -s $DST_IP -p udp --sport $NAT_TARGET_PORT \
        -j LOG --log-prefix "PRE_ROUTING_REPLY: " --log-level 6
        
    # === COMPREHENSIVE DEBUGGING ===
    # Track all traffic to/from the target IP (catch-all)
    iptables -t raw -I PREROUTING -d $DST_IP \
        -j LOG --log-prefix "ALL_TO_$DST_IP: " --log-level 6
        
    iptables -t raw -I PREROUTING -s $DST_IP \
        -j LOG --log-prefix "ALL_FROM_$DST_IP: " --log-level 6
    
    echo "✅ VXLAN pipeline tracing rules installed!"
    echo "📊 Monitor with: sudo journalctl -f -k | grep -E '(PRE_ROUTING|POST_ROUTING|FORWARD|INPUT|OUTPUT)'"
}

cleanup_tracing() {
    validate_environment "stop"
    echo "🧹 Cleaning up VXLAN pipeline tracing rules..."
    
    local failed_rules=0
    
    # Remove incoming packet rules (to SOURCE_PORT)
    iptables -t raw -D PREROUTING -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "PRE_ROUTING_IN: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t filter -D FORWARD -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "FORWARD_IN: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t filter -D INPUT -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "INPUT_IN: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    # Remove outgoing packet rules (to NAT_PORT)
    iptables -t filter -D OUTPUT -d $DST_IP -p udp --dport $NAT_TARGET_PORT \
        -j LOG --log-prefix "OUTPUT_NAT: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t nat -D POSTROUTING -d $DST_IP -p udp --dport $NAT_TARGET_PORT \
        -j LOG --log-prefix "POST_ROUTING_NAT: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t filter -D FORWARD -d $DST_IP -p udp --dport $NAT_TARGET_PORT \
        -j LOG --log-prefix "FORWARD_NAT: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    # Remove bidirectional rules
    iptables -t raw -D PREROUTING -s $DST_IP -p udp --sport $NAT_TARGET_PORT \
        -j LOG --log-prefix "PRE_ROUTING_REPLY: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    # Remove catch-all rules
    iptables -t raw -D PREROUTING -d $DST_IP \
        -j LOG --log-prefix "ALL_TO_$DST_IP: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t raw -D PREROUTING -s $DST_IP \
        -j LOG --log-prefix "ALL_FROM_$DST_IP: " --log-level 6 2>/dev/null || ((failed_rules++))
    
    if [[ $failed_rules -eq 0 ]]; then
        echo "✅ All tracing rules removed successfully"
    else
        echo "⚠️  $failed_rules rules were already removed or failed to remove"
    fi
}

show_logs() {
    echo "📋 Recent netfilter logs (last 50 lines):"
    journalctl -k --since "5 minutes ago" | grep -E "(PRE_ROUTING|POST_ROUTING|FORWARD|INPUT|OUTPUT)" | tail -50
}

monitor_logs() {
    echo "🔍 Monitoring packet flow in real-time (Ctrl+C to stop)..."
    echo "Run your test in another terminal now!"
    echo "----------------------------------------"
    journalctl -f -k | grep --line-buffered -E "(PRE_ROUTING|POST_ROUTING|FORWARD|INPUT|OUTPUT|ALL_PRE)"
}

check_routing_decision() {
    echo "🛣️  Routing Analysis for $SRC_IP → $DST_IP:"
    echo "----------------------------------------"
    
    # Show which interface will be used
    echo "Route lookup result:"
    ip route get $DST_IP from $SRC_IP || echo "Route lookup failed"
    
    echo -e "\nActive routes for $DST_IP subnet:"
    ip route show | grep "172.30.82.0/23"
    
    echo -e "\nARP entries for $DST_IP:"
    ip neigh show $DST_IP
    
    echo -e "\nInterface IP addresses:"
    ip addr show ens5 | grep "inet "
    ip addr show ens6 | grep "inet "
}

case "${1:-help}" in
    "start")
        setup_tracing
        check_routing_decision
        echo -e "\n🚀 Now run: sudo ./debug_packet_flow.sh monitor"
        echo "   In another terminal: sudo ./debug_packet_flow.sh test"
        ;;
    "stop")
        cleanup_tracing
        ;;
    "show")
        show_logs
        ;;
    "monitor")
        monitor_logs
        ;;
    "test")
        validate_environment "test"
        echo "🧪 Sending VXLAN test packet: ANY → $DST_IP:$DST_PORT"
        echo "   🔄 Expected NAT result: ANY → $DST_IP:$NAT_TARGET_PORT"
        python3 ./send_exact_packet.py
        ;;
    "route")
        check_routing_decision
        ;;
    "help"|*)
        echo "Usage: sudo $0 {start|stop|show|monitor|test|route}"
        echo ""
        echo "🎯 VXLAN Pipeline Packet Flow Debugger"
        echo "======================================"
        echo "Configuration loaded from .env file:"
        echo "  📥 Monitors packets TO: $DST_IP:$DST_PORT (SOURCE_PORT)"
        echo "  📤 Expects NAT output TO: $DST_IP:$NAT_TARGET_PORT (NAT_PORT)"
        echo ""
        echo "Commands:"
        echo "  start   - Install VXLAN pipeline tracing rules"
        echo "  stop    - Remove all tracing rules" 
        echo "  show    - Show recent netfilter logs"
        echo "  monitor - Real-time log monitoring"
        echo "  test    - Send VXLAN test packet"
        echo "  route   - Analyze routing decisions"
        echo ""
        echo "🚀 Workflow:"
        echo "  1. sudo $0 start      # Install VXLAN tracing"
        echo "  2. sudo $0 monitor    # Monitor in terminal 1" 
        echo "  3. sudo $0 test       # Send VXLAN test in terminal 2"
        echo "  4. sudo $0 stop       # Cleanup when done"
        echo ""
        echo "💡 Expected packet flow:"
        echo "   📥 Input:  ANY → $DST_IP:$DST_PORT"
        echo "   🔄 XDP NAT: Process via VXLAN pipeline" 
        echo "   📤 Output: ANY → $DST_IP:$NAT_TARGET_PORT"
        ;;
esac