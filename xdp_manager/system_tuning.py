"""
System performance tuning for high-performance packet processing
Implements comprehensive system optimizations for XDP pipeline performance
"""

import os
import subprocess
import glob
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from .utils import CommandRunner, Logger
from .models import ValidationResult

class SystemTuner:
    """Apply comprehensive system tuning for high-performance packet processing"""
    
    def __init__(self, runner: Optional[CommandRunner] = None, logger: Optional[Logger] = None):
        self.runner = runner or CommandRunner()
        self.logger = logger or Logger("system_tuner")
        self.applied_changes = []
        
    def apply_system_tuning(self, interface: str) -> bool:
        """Apply comprehensive system tuning for optimal packet processing performance"""
        self.logger.info("Applying system tuning for high-performance packet processing...")
        
        tuning_applied = False
        
        try:
            # Network buffer tuning for high throughput
            if self._tune_network_buffers():
                tuning_applied = True
                
            # Network device budget for packet processing
            if self._tune_network_device_budget():
                tuning_applied = True
                
            # Real-time scheduling optimization
            if self._tune_realtime_scheduler():
                tuning_applied = True
                
            # Ring buffer parameters for XDP
            if self._tune_ring_buffers(interface):
                tuning_applied = True
                
            # CPU scaling governor for performance
            if self._tune_cpu_governor():
                tuning_applied = True
                
            # IRQ affinity optimization
            if self._tune_irq_affinity(interface):
                tuning_applied = True
                
            # Create persistent tuning configuration
            self._create_persistent_tuning()
            
            if tuning_applied:
                self.logger.info("✓ System tuning applied successfully")
            else:
                self.logger.info("✓ System already optimally tuned")
                
            return True
            
        except Exception as e:
            self.logger.error(f"System tuning failed: {e}")
            return False
    
    def _tune_network_buffers(self) -> bool:
        """Optimize network buffer sizes for high throughput"""
        tuning_applied = False
        
        # Get current values
        current_rmem = self._get_sysctl_value("net.core.rmem_max", "0")
        current_wmem = self._get_sysctl_value("net.core.wmem_max", "0")
        
        target_buffer_size = 134217728  # 128MB
        
        # Tune receive buffer
        if int(current_rmem) < target_buffer_size:
            current_mb = int(current_rmem) // (1024 * 1024)
            self.logger.info(f"• Increasing receive buffer size: {current_mb}MB → 128MB")
            if self._set_sysctl("net.core.rmem_max", str(target_buffer_size)):
                tuning_applied = True
        else:
            current_mb = int(current_rmem) // (1024 * 1024)
            self.logger.info(f"✓ Receive buffer size optimal: {current_mb}MB")
            
        # Tune send buffer
        if int(current_wmem) < target_buffer_size:
            current_mb = int(current_wmem) // (1024 * 1024)
            self.logger.info(f"• Increasing send buffer size: {current_mb}MB → 128MB")
            if self._set_sysctl("net.core.wmem_max", str(target_buffer_size)):
                tuning_applied = True
        else:
            current_mb = int(current_wmem) // (1024 * 1024)
            self.logger.info(f"✓ Send buffer size optimal: {current_mb}MB")
            
        return tuning_applied
    
    def _tune_network_device_budget(self) -> bool:
        """Optimize network device processing budget"""
        current_budget = self._get_sysctl_value("net.core.netdev_budget", "300")
        target_budget = 600
        
        if int(current_budget) < target_budget:
            self.logger.info(f"• Increasing network device budget: {current_budget} → {target_budget}")
            return self._set_sysctl("net.core.netdev_budget", str(target_budget))
        else:
            self.logger.info(f"✓ Network device budget optimal: {current_budget}")
            return False
    
    def _tune_realtime_scheduler(self) -> bool:
        """Optimize real-time scheduling for packet processing"""
        current_rt_runtime = self._get_sysctl_value("kernel.sched_rt_runtime_us", "950000")
        target_rt_runtime = 950000
        
        if int(current_rt_runtime) != target_rt_runtime:
            self.logger.info(f"• Optimizing real-time scheduler: {current_rt_runtime} → {target_rt_runtime}µs")
            return self._set_sysctl("kernel.sched_rt_runtime_us", str(target_rt_runtime))
        else:
            self.logger.info(f"✓ Real-time scheduler optimal: {current_rt_runtime}µs")
            return False
    
    def _tune_ring_buffers(self, interface: str) -> bool:
        """Optimize ring buffer parameters for XDP"""
        try:
            # Get current and maximum ring buffer sizes
            result = self.runner.run(["ethtool", "-g", interface], check=False)
            if result.returncode != 0:
                self.logger.warning(f"Could not get ring buffer info for {interface}")
                return False
                
            lines = result.stdout.strip().split('\n')
            max_rx_ring = None
            current_rx_ring = None
            
            # Parse ethtool output
            for i, line in enumerate(lines):
                if "RX:" in line and "Pre-set maximums:" in lines[max(0, i-5):i]:
                    max_rx_ring = int(line.split()[-1])
                elif "RX:" in line and max_rx_ring is not None:
                    current_rx_ring = int(line.split()[-1])
                    break
            
            if max_rx_ring and current_rx_ring and current_rx_ring < max_rx_ring:
                self.logger.info(f"• Optimizing RX ring buffer: {current_rx_ring} → {max_rx_ring}")
                result = self.runner.run(["sudo", "ethtool", "-G", interface, "rx", str(max_rx_ring)], check=False)
                if result.returncode == 0:
                    self.logger.info("✓ RX ring buffer optimized")
                    return True
                else:
                    self.logger.warning("⚠ RX ring buffer optimization failed (may not be supported)")
            elif current_rx_ring == max_rx_ring and current_rx_ring > 0:
                self.logger.info(f"✓ RX ring buffer optimal: {current_rx_ring}")
                
        except Exception as e:
            self.logger.warning(f"Ring buffer optimization failed: {e}")
            
        return False
    
    def _tune_cpu_governor(self) -> bool:
        """Set CPU governor to performance mode"""
        try:
            # Check current CPU governor
            governor_path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
            if not Path(governor_path).exists():
                self.logger.info("✓ CPU frequency scaling not available")
                return False
                
            with open(governor_path, 'r') as f:
                current_gov = f.read().strip()
                
            if current_gov != "performance":
                self.logger.info(f"• Setting CPU governor: {current_gov} → performance")
                
                # Set performance governor for all CPUs
                cpu_paths = glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")
                for cpu_path in cpu_paths:
                    try:
                        result = self.runner.run(
                            ["sudo", "bash", "-c", f"echo performance > {cpu_path}"],
                            check=False
                        )
                        if result.returncode != 0:
                            raise Exception("Failed to set governor")
                    except Exception:
                        continue
                        
                self.logger.info("✓ CPU governor set to performance")
                return True
            else:
                self.logger.info(f"✓ CPU governor optimal: {current_gov}")
                return False
                
        except Exception as e:
            self.logger.warning(f"CPU governor optimization failed: {e}")
            return False
    
    def _tune_irq_affinity(self, interface: str) -> bool:
        """Optimize IRQ affinity for network interface"""
        try:
            # Stop irqbalance for manual IRQ optimization
            irqbalance_running = False
            try:
                result = self.runner.run(["pgrep", "irqbalance"], check=False)
                if result.returncode == 0:
                    irqbalance_running = True
                    self.logger.info("• Stopping irqbalance for manual IRQ optimization")
                    self.runner.run(["sudo", "systemctl", "stop", "irqbalance"], check=False)
            except Exception:
                pass
            
            # Get IRQ numbers for the interface
            try:
                with open("/proc/interrupts", 'r') as f:
                    interrupts_content = f.read()
            except Exception:
                self.logger.warning("Could not read /proc/interrupts")
                return False
            
            irq_nums = []
            for line in interrupts_content.split('\n'):
                if interface in line:
                    irq_num = line.split(':')[0].strip()
                    if irq_num.isdigit():
                        irq_nums.append(irq_num)
            
            if irq_nums:
                self.logger.info(f"• Optimizing IRQ affinity for {interface}")
                cpu_mask = 1
                tuning_applied = False
                
                for irq in irq_nums:
                    affinity_path = f"/proc/irq/{irq}/smp_affinity"
                    if Path(affinity_path).exists():
                        try:
                            mask_hex = f"{cpu_mask:x}"
                            result = self.runner.run(
                                ["sudo", "bash", "-c", f"echo {mask_hex} > {affinity_path}"],
                                check=False
                            )
                            if result.returncode == 0:
                                tuning_applied = True
                                
                            # Rotate through CPUs 0-3
                            cpu_mask = (cpu_mask << 1) % 16
                            if cpu_mask == 0:
                                cpu_mask = 1
                        except Exception:
                            continue
                
                if tuning_applied:
                    self.logger.info("✓ IRQ affinity optimized")
                    return True
            else:
                self.logger.info(f"✓ No IRQs found for {interface}")
                
        except Exception as e:
            self.logger.warning(f"IRQ affinity optimization failed: {e}")
            
        return False
    
    def _create_persistent_tuning(self) -> bool:
        """Create persistent system tuning configuration"""
        sysctl_conf = "/etc/sysctl.d/99-xdp-vxlan-performance.conf"
        
        self.logger.info("Creating persistent system tuning configuration...")
        
        try:
            config_content = """# XDP VXLAN Pipeline Performance Tuning
# Applied automatically during pipeline startup

# Network buffer sizes for high-throughput packet processing
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728

# Network device processing budget
net.core.netdev_budget = 600

# Real-time scheduler optimization for packet processing
kernel.sched_rt_runtime_us = 950000

# Additional network performance tuning
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 32768
net.ipv4.tcp_congestion_control = bbr
"""
            
            result = self.runner.run(
                ["sudo", "tee", sysctl_conf],
                input=config_content,
                check=False
            )
            
            if result.returncode == 0:
                self.logger.info(f"✓ Persistent tuning configuration created: {sysctl_conf}")
                return True
            else:
                self.logger.warning("Could not create persistent tuning configuration")
                return False
                
        except Exception as e:
            self.logger.warning(f"Failed to create persistent tuning: {e}")
            return False
    
    def _get_sysctl_value(self, parameter: str, default: str = "0") -> str:
        """Get current sysctl parameter value"""
        try:
            result = self.runner.run(["sysctl", "-n", parameter], check=False)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return default
    
    def _set_sysctl(self, parameter: str, value: str) -> bool:
        """Set sysctl parameter value"""
        try:
            result = self.runner.run(
                ["sudo", "sysctl", "-w", f"{parameter}={value}"],
                check=False
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def validate_system_readiness(self) -> ValidationResult:
        """Validate system is ready for high-performance packet processing"""
        errors = []
        warnings = []
        
        # Check kernel version for XDP support
        try:
            with open("/proc/version", 'r') as f:
                kernel_version = f.read()
            if "4.1" in kernel_version or "3." in kernel_version:
                errors.append("Kernel version may not support XDP (requires 4.18+)")
        except Exception:
            warnings.append("Could not determine kernel version")
        
        # Check available memory
        try:
            with open("/proc/meminfo", 'r') as f:
                meminfo = f.read()
            for line in meminfo.split('\n'):
                if line.startswith('MemAvailable:'):
                    mem_kb = int(line.split()[1])
                    mem_gb = mem_kb / (1024 * 1024)
                    if mem_gb < 4:
                        warnings.append(f"Low available memory: {mem_gb:.1f}GB (recommend 8GB+)")
                    break
        except Exception:
            warnings.append("Could not check available memory")
        
        # Check for required tools
        required_tools = ["bpftool", "ethtool", "sysctl"]
        for tool in required_tools:
            result = self.runner.run(["which", tool], check=False)
            if result.returncode != 0:
                errors.append(f"Required tool not found: {tool}")
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )