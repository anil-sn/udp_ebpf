# XDP VXLAN Pipeline

High-performance AWS Traffic Mirror packet processing system using eBPF/XDP for enterprise-grade VXLAN traffic analysis at 85K+ PPS.

The XDP VXLAN Pipeline processes AWS Traffic Mirror VXLAN packets through unified AWS VMs with integrated XDP and IPSec processing, delivering processed traffic to GCP Kubernetes clusters via optimized fragmentation handling.

See [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md) for comprehensive technical documentation.