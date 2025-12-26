#!/bin/bash
# Comprehensive packet flow debugging using netfilter hooks
# Usage: sudo ./debug_packet_flow.sh start|stop|show

set -euo pipefail

# Configuration - modify these as needed
SRC_IP="${SRC_IP:-172.30.82.13}"
DST_IP="${DST_IP:-172.30.82.95}"
DST_PORT="${DST_PORT:-1035}"
INTERFACE="${INTERFACE:-ens6}"

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
    echo "🔍 Setting up packet flow tracing for $SRC_IP → $DST_IP:$DST_PORT"
    
    # Clear existing rules
    cleanup_tracing 2>/dev/null || true
    
    # PREROUTING - Track incoming packets
    iptables -t raw -I PREROUTING -s $SRC_IP -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "PRE_ROUTING: " --log-level 6
    
    # FORWARD - Track forwarded packets  
    iptables -t filter -I FORWARD -s $SRC_IP -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "FORWARD: " --log-level 6
        
    # INPUT - Track packets destined for local delivery
    iptables -t filter -I INPUT -s $SRC_IP -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "INPUT: " --log-level 6
    
    # OUTPUT - Track locally generated packets
    iptables -t filter -I OUTPUT -s $SRC_IP -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "OUTPUT: " --log-level 6
    
    # POSTROUTING - Track outgoing packets
    iptables -t nat -I POSTROUTING -s $SRC_IP -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "POST_ROUTING: " --log-level 6
    
    # Track both directions
    iptables -t raw -I PREROUTING -s $DST_IP -d $SRC_IP -p udp --sport $DST_PORT \
        -j LOG --log-prefix "PRE_ROUTING_REPLY: " --log-level 6
        
    # Additional debugging - track all traffic to/from these IPs
    iptables -t raw -I PREROUTING -s $SRC_IP -d $DST_IP \
        -j LOG --log-prefix "ALL_PRE_$SRC_IP->$DST_IP: " --log-level 6
        
    iptables -t raw -I PREROUTING -s $DST_IP -d $SRC_IP \
        -j LOG --log-prefix "ALL_PRE_$DST_IP->$SRC_IP: " --log-level 6
    
    echo "✅ Tracing rules installed. Monitor with: sudo journalctl -f -k | grep -E '(PRE_ROUTING|POST_ROUTING|FORWARD|INPUT|OUTPUT)'"
}

cleanup_tracing() {
    validate_environment "stop"
    echo "🧹 Cleaning up tracing rules..."
    
    local failed_rules=0
    
    # Remove all our LOG rules (safer than flush)
    iptables -t raw -D PREROUTING -s $SRC_IP -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "PRE_ROUTING: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t filter -D FORWARD -s $SRC_IP -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "FORWARD: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t filter -D INPUT -s $SRC_IP -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "INPUT: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t filter -D OUTPUT -s $SRC_IP -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "OUTPUT: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t nat -D POSTROUTING -s $SRC_IP -d $DST_IP -p udp --dport $DST_PORT \
        -j LOG --log-prefix "POST_ROUTING: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t raw -D PREROUTING -s $DST_IP -d $SRC_IP -p udp --sport $DST_PORT \
        -j LOG --log-prefix "PRE_ROUTING_REPLY: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t raw -D PREROUTING -s $SRC_IP -d $DST_IP \
        -j LOG --log-prefix "ALL_PRE_$SRC_IP->$DST_IP: " --log-level 6 2>/dev/null || ((failed_rules++))
        
    iptables -t raw -D PREROUTING -s $DST_IP -d $SRC_IP \
        -j LOG --log-prefix "ALL_PRE_$DST_IP->$SRC_IP: " --log-level 6 2>/dev/null || ((failed_rules++))
    
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
        echo "🧪 Sending test packet: $SRC_IP → $DST_IP:$DST_PORT"
        python3 ./send_exact_packet.py
        ;;
    "route")
        check_routing_decision
        ;;
    "help"|*)
        echo "Usage: sudo $0 {start|stop|show|monitor|test|route}"
        echo ""
        echo "Commands:"
        echo "  start   - Install netfilter tracing rules"
        echo "  stop    - Remove all tracing rules" 
        echo "  show    - Show recent logs"
        echo "  monitor - Real-time log monitoring"
        echo "  test    - Send test packet"
        echo "  route   - Analyze routing decisions"
        echo ""
        echo "Workflow:"
        echo "  1. sudo $0 start      # Install tracing"
        echo "  2. sudo $0 monitor    # Monitor in terminal 1" 
        echo "  3. sudo $0 test       # Send test in terminal 2"
        echo "  4. sudo $0 stop       # Cleanup when done"
        ;;
esac