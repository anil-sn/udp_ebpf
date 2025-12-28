#!/usr/bin/env python3
"""
CLI module for XDP Manager
Entry point for the command-line interface
"""

# Import the main CLI class and entry point
from .xdp_manager_cli import XDPManagerCLI, main

__all__ = ['XDPManagerCLI', 'main']

# This allows the module to be run directly
if __name__ == '__main__':
    import sys
    sys.exit(main())