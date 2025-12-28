#!/bin/bash
# XDP Manager Autocompletion Setup Script

echo "Setting up autocompletion for xdp-manager..."

# Check if argcomplete is installed
if ! python -c "import argcomplete" 2>/dev/null; then
    echo "Installing argcomplete..."
    pip install argcomplete
fi

# Register global completion
echo "Registering global autocompletion..."
if command -v register-python-argcomplete >/dev/null 2>&1; then
    # For the Python module
    register-python-argcomplete xdp_manager.cli >> ~/.bashrc
    
    # For the CLI script
    register-python-argcomplete xdp-manager >> ~/.bashrc
    
    echo "Added to ~/.bashrc"
fi

# Create completion script for manual sourcing
echo "Creating completion script..."
cat > xdp-manager-completion.sh << 'EOF'
# XDP Manager Bash Completion
# Source this file or add to ~/.bashrc

# Enable completion for the Python module
eval "$(register-python-argcomplete xdp_manager.cli)"

# Enable completion for the CLI script  
eval "$(register-python-argcomplete xdp-manager)"

# Custom completions for common options
_xdp_manager_interfaces() {
    local interfaces=$(ip link show | grep '^[0-9]' | cut -d: -f2 | tr -d ' ')
    COMPREPLY=($(compgen -W "$interfaces" -- "$2"))
}

_xdp_manager_programs() {
    local programs=$(find . -name "*.bpf.o" 2>/dev/null)
    COMPREPLY=($(compgen -W "$programs" -- "$2"))
}

# Register custom completions
complete -F _xdp_manager_interfaces xdp-manager -o interface
complete -F _xdp_manager_programs xdp-manager -o program
EOF

echo "Created xdp-manager-completion.sh"

# Setup instructions
cat << EOF

✅ Autocompletion setup complete!

To enable autocompletion:

1. For current session:
   source xdp-manager-completion.sh

2. For all future sessions:
   echo 'source $(pwd)/xdp-manager-completion.sh' >> ~/.bashrc
   source ~/.bashrc

3. Or copy to system-wide location:
   sudo cp xdp-manager-completion.sh /etc/bash_completion.d/

Usage examples with autocompletion:
   xdp-manager start --interface <TAB>    # Shows available interfaces
   xdp-manager start --program <TAB>      # Shows available BPF programs
   xdp-manager allowlist <TAB>            # Shows allowlist subcommands
   xdp-manager stats --<TAB>              # Shows all stats options

EOF