#!/bin/bash
# Quick build and path verification script

echo "XDP VXLAN Pipeline - Build Verification"
echo "======================================"

# Check if we're in the right directory
if [ ! -f "xdp.sh" ] || [ ! -d "src" ]; then
    echo "❌ Please run this script from the project root directory"
    echo "   (directory containing xdp.sh and src/)"
    exit 1
fi

echo "✓ Running from correct directory"

# Build the project
echo ""
echo "Building project..."
cd src
if make clean && make all; then
    echo "✓ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi
cd ..

# Verify build artifacts
echo ""
echo "Verifying build artifacts..."
if [ -f "src/vxlan_loader" ]; then
    echo "✓ vxlan_loader executable found"
else
    echo "❌ vxlan_loader executable missing"
    exit 1
fi

if [ -f "src/vxlan_pipeline.bpf.o" ]; then
    echo "✓ vxlan_pipeline.bpf.o found"
else
    echo "❌ vxlan_pipeline.bpf.o missing"
    exit 1
fi

# Check configuration
echo ""
echo "Checking configuration..."
if [ -f ".env" ]; then
    echo "✓ .env file found"
else
    echo "⚠️  .env file missing, creating default..."
    cp .env.example .env
    echo "✓ Default .env created"
fi

echo ""
echo "🎉 All checks passed! You can now run:"
echo "   ./xdp.sh start"