"""
Core XDP pipeline management and orchestration
"""

import os
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from .models import PipelineStatus, CompilationResult, SystemInfo
from .utils import CommandRunner, Logger, PerformanceMonitor
from .config import ConfigManager
from .network import NetworkManager
from .bpf_maps import BPFMapManager
from .allowlist import AllowlistManager
from .display import DisplayManager

class XDPPipeline:
    """Main XDP pipeline orchestrator with advanced management capabilities"""
    
    def __init__(self, config_manager: Optional[ConfigManager] = None):
        self.config = config_manager or ConfigManager()
        self.logger = Logger("xdp_pipeline")
        self.runner = CommandRunner(self.logger)
        self.network = NetworkManager(self.runner, self.logger)
        self.bpf_maps = BPFMapManager(self.runner, self.logger)
        self.allowlist = AllowlistManager(
            str(self.config.get_allowlist_path()),
            self.runner,
            self.logger
        )
        self.display = DisplayManager(self.logger)
        self.perf_monitor = PerformanceMonitor()
        
        # Load configuration
        self.config.load_config()
        
    def start(self, interface: Optional[str] = None, force: bool = False) -> bool:
        """Start XDP pipeline with comprehensive validation and deployment"""
        try:
            self.logger.info("Starting XDP pipeline deployment...")
            
            with self.perf_monitor.measure("pipeline_start"):
                # Pre-deployment validation
                if not self._pre_deployment_checks(interface, force):
                    return False
                
                # Determine target interface
                target_interface = interface or self.config.pipeline_config.ingress_interface
                if not target_interface:
                    target_interface = self.network.get_recommended_interface()
                    if not target_interface:
                        self.logger.error("No suitable network interface found")
                        return False
                
                # Validate interface
                validation = self.network.validate_interface(target_interface)
                if not validation.valid:
                    for error in validation.errors:
                        self.logger.error(error)
                    if not force:
                        return False
                
                # Compilation
                compilation_result = self._compile_bpf_program()
                if not compilation_result.success:
                    self.logger.error(f"BPF compilation failed: {compilation_result.error_message}")
                    return False
                
                # Deploy to interface
                if not self._deploy_to_interface(target_interface, compilation_result.output_file):
                    return False
                
                # Load allowlist
                if self.config.get_allowlist_path().exists():
                    self._load_allowlist()
                
                # Post-deployment verification
                if not self._post_deployment_verification(target_interface):
                    self.logger.warning("Post-deployment verification failed")
                
                # Update configuration
                self.config.update_interface(target_interface)
                
            duration = self.perf_monitor.end_timer("pipeline_start")
            self.logger.info(f"Pipeline started successfully in {duration:.2f}s on {target_interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Pipeline start failed: {e}")
            return False
    
    def stop(self, cleanup: bool = True) -> bool:
        """Stop XDP pipeline with optional cleanup"""
        try:
            self.logger.info("Stopping XDP pipeline...")
            
            # Detach from all interfaces
            detached_interfaces = self.network.detach_all_xdp()
            
            if detached_interfaces:
                self.logger.info(f"Detached XDP from interfaces: {', '.join(detached_interfaces)}")
            else:
                self.logger.info("No XDP programs were attached")
            
            # Optional cleanup
            if cleanup:
                self._cleanup_resources()
            
            self.logger.info("Pipeline stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Pipeline stop failed: {e}")
            return False
    
    def restart(self, interface: Optional[str] = None) -> bool:
        """Restart pipeline with graceful shutdown and startup"""
        self.logger.info("Restarting XDP pipeline...")
        
        # Stop current pipeline
        if not self.stop(cleanup=False):
            self.logger.error("Failed to stop pipeline for restart")
            return False
        
        # Brief pause for cleanup
        time.sleep(1)
        
        # Start with same or new interface
        return self.start(interface)
    
    def get_status(self) -> PipelineStatus:
        """Get current pipeline operational status"""
        try:
            # Check if BPF program exists
            if not self.config.get_bpf_path().exists():
                return PipelineStatus.ERROR
            
            # Check if XDP is loaded
            if self._is_xdp_loaded():
                # Verify maps exist and are accessible
                if self._verify_maps():
                    return PipelineStatus.RUNNING
                else:
                    return PipelineStatus.ERROR
            else:
                return PipelineStatus.STOPPED
                
        except Exception:
            return PipelineStatus.UNKNOWN
    
    def get_detailed_status(self) -> Dict[str, Any]:
        """Get comprehensive status information"""
        status = {
            'pipeline_status': self.get_status(),
            'configuration': {
                'interface': self.config.pipeline_config.ingress_interface,
                'src_directory': str(self.config.get_src_path()),
                'bpf_program': str(self.config.get_bpf_path()),
                'allowlist_file': str(self.config.get_allowlist_path())
            },
            'system': self._get_system_info(),
            'network': {
                'interfaces': len(self.network.get_interfaces()),
                'recommended_interface': self.network.get_recommended_interface()
            },
            'bpf_maps': {
                'total_maps': len(self.bpf_maps.list_maps()),
                'validation': self.bpf_maps.validate_maps()
            },
            'allowlist': self.allowlist.get_status()
        }
        
        return status
    
    def compile(self, force: bool = False) -> CompilationResult:
        """Compile BPF program with advanced optimization"""
        return self._compile_bpf_program(force)
    
    def validate_configuration(self) -> bool:
        """Validate entire pipeline configuration"""
        validation = self.config.validate_config()
        
        if not validation.valid:
            self.logger.error("Configuration validation failed:")
            for error in validation.errors:
                self.logger.error(f"  - {error}")
        
        if validation.warnings:
            self.logger.warning("Configuration warnings:")
            for warning in validation.warnings:
                self.logger.warning(f"  - {warning}")
        
        return validation.valid
    
    def optimize_performance(self) -> bool:
        """Apply performance optimizations"""
        try:
            self.logger.info("Applying performance optimizations...")
            
            # Enable performance mode in config
            self.config.enable_performance_mode()
            
            # System tuning
            tuning_commands = [
                # CPU scaling governor
                ['sudo', 'bash', '-c', 'echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor'],
                # Network interface optimization
                ['sudo', 'ethtool', '-K', self.config.pipeline_config.ingress_interface, 'gro', 'off'],
                ['sudo', 'ethtool', '-K', self.config.pipeline_config.ingress_interface, 'lro', 'off'],
                # Kernel network buffers
                ['sudo', 'sysctl', '-w', 'net.core.rmem_max=134217728'],
                ['sudo', 'sysctl', '-w', 'net.core.wmem_max=134217728'],
            ]
            
            success_count = 0
            for cmd in tuning_commands:
                try:
                    self.runner.run(cmd, check=False)
                    success_count += 1
                except:
                    pass
            
            self.logger.info(f"Applied {success_count}/{len(tuning_commands)} optimizations")
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"Performance optimization failed: {e}")
            return False
    
    def _pre_deployment_checks(self, interface: Optional[str], force: bool) -> bool:
        """Comprehensive pre-deployment validation"""
        # Configuration validation
        if not self.validate_configuration():
            if not force:
                return False
        
        # System requirements
        system_info = self._get_system_info()
        if not system_info.bpf_jit_enabled:
            self.logger.warning("BPF JIT is disabled - performance may be impacted")
        
        # Tool availability
        tools = system_info.available_interfaces  # This should be tools check
        missing_tools = [tool for tool, available in tools if not available] if isinstance(tools, dict) else []
        if missing_tools and not force:
            self.logger.error(f"Required tools missing: {', '.join(missing_tools)}")
            return False
        
        # Interface validation
        if interface and not self.network.interface_exists(interface):
            self.logger.error(f"Interface {interface} does not exist")
            return False
        
        return True
    
    def _compile_bpf_program(self, force: bool = False) -> CompilationResult:
        """Compile BPF program using the working Makefile"""
        result = CompilationResult(success=False)
        
        try:
            with self.perf_monitor.measure("compilation"):
                bpf_source = self.config.get_bpf_path()
                output_file = bpf_source.with_suffix('.o')
                
                # Check if recompilation needed
                if not force and output_file.exists() and output_file.stat().st_mtime > bpf_source.stat().st_mtime:
                    result.success = True
                    result.output_file = str(output_file)
                    self.logger.info("BPF program is up to date, skipping compilation")
                    return result
                
                # Use Makefile for compilation (proven working solution)
                src_path = self.config.get_src_path()
                original_cwd = os.getcwd()
                
                try:
                    # Change to source directory where Makefile is located
                    os.chdir(src_path)
                    
                    # Clean any existing object files first
                    clean_cmd = ['make', 'clean']
                    self.logger.info("Cleaning previous build artifacts...")
                    self.runner.run(clean_cmd, capture=True)
                    
                    # Compile BPF program using Makefile
                    compile_cmd = ['make', str(output_file.name)]
                    self.logger.info(f"Compiling BPF program using Makefile: {' '.join(compile_cmd)}")
                    
                    compile_result = self.runner.run(compile_cmd, capture=True)
                    
                    # Check if output file was created
                    if output_file.exists():
                        result.success = True
                        result.output_file = str(output_file)
                        self.logger.info(f"BPF program compiled successfully: {output_file}")
                        
                        if compile_result.stderr:
                            result.warnings = [line for line in compile_result.stderr.split('\n') if line.strip()]
                    else:
                        result.error_message = f"Compilation did not produce output file: {output_file}"
                        self.logger.error(result.error_message)
                        
                finally:
                    os.chdir(original_cwd)
            
            result.compilation_time = self.perf_monitor.end_timer("compilation")
            self.logger.info(f"Compilation completed in {result.compilation_time:.2f}s")
            
        except Exception as e:
            result.error_message = str(e)
            self.logger.error(f"Compilation failed: {e}")
        
        return result
    
    def _deploy_to_interface(self, interface: str, program_file: str) -> bool:
        """Deploy compiled BPF program to network interface"""
        try:
            self.logger.info(f"Deploying BPF program to interface {interface}")
            
            # Attach XDP program
            success = self.network.attach_xdp(interface, program_file)
            
            if success:
                # Verify attachment
                time.sleep(0.5)  # Brief delay for attachment
                attached = self.network.get_interface(interface)
                if attached and attached.xdp_attached:
                    self.logger.info(f"XDP program successfully attached to {interface}")
                    return True
                else:
                    self.logger.error(f"XDP attachment verification failed for {interface}")
                    return False
            
            return False
            
        except Exception as e:
            self.logger.error(f"Deployment to {interface} failed: {e}")
            return False
    
    def _load_allowlist(self) -> bool:
        """Load IP allowlist into BPF maps"""
        try:
            self.logger.info("Loading IP allowlist...")
            
            sync_result = self.allowlist.sync_to_bpf()
            
            if sync_result.success:
                self.logger.info(f"Loaded {sync_result.total_entries} allowlist entries")
                return True
            else:
                self.logger.error("Allowlist loading failed:")
                for error in sync_result.errors:
                    self.logger.error(f"  - {error}")
                return False
                
        except Exception as e:
            self.logger.error(f"Allowlist loading failed: {e}")
            return False
    
    def _post_deployment_verification(self, interface: str) -> bool:
        """Verify deployment was successful"""
        try:
            # Check XDP attachment
            iface_info = self.network.get_interface(interface)
            if not (iface_info and iface_info.xdp_attached):
                return False
            
            # Check BPF maps
            if not self._verify_maps():
                return False
            
            # Check basic statistics
            stats = self.bpf_maps.get_pipeline_stats()
            self.logger.debug(f"Initial stats: {stats.packets_processed} processed")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Post-deployment verification failed: {e}")
            return False
    
    def _is_xdp_loaded(self) -> bool:
        """Check if any XDP program is currently loaded"""
        try:
            result = self.runner.run(['sudo', 'bpftool', 'net', 'list'], capture=True, check=False)
            return 'xdp' in result.stdout.lower() if result.returncode == 0 else False
        except:
            return False
    
    def _verify_maps(self) -> bool:
        """Verify required BPF maps exist and are accessible"""
        try:
            map_validation = self.bpf_maps.validate_maps()
            required_maps = ['stats_map', 'ip_allowlist_lpm']
            
            for map_name in required_maps:
                if not map_validation.get(map_name, False):
                    self.logger.error(f"Required BPF map missing: {map_name}")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Map verification failed: {e}")
            return False
    
    def _get_system_info(self) -> SystemInfo:
        """Gather comprehensive system information"""
        try:
            from .utils import SystemInfo as SysInfoUtil
            sys_util = SysInfoUtil(self.runner)
            
            return SystemInfo(
                kernel_version=sys_util.get_kernel_version(),
                bpf_jit_enabled=sys_util.is_bpf_jit_enabled(),
                available_interfaces=sys_util.get_network_interfaces(),
                cpu_count=sys_util.get_cpu_count(),
                memory_mb=sys_util.get_memory_mb()
            )
        except:
            return SystemInfo(
                kernel_version="unknown",
                bpf_jit_enabled=False,
                available_interfaces=[],
                cpu_count=1,
                memory_mb=0
            )
    
    def _cleanup_resources(self) -> None:
        """Clean up system resources and temporary files"""
        try:
            # Clean up BPF maps (optional)
            # self.bpf_maps.clear_map('stats_map')
            
            # Remove temporary files
            temp_files = self.config.get_src_path().glob("*.tmp")
            for temp_file in temp_files:
                try:
                    temp_file.unlink()
                except:
                    pass
            
            self.logger.debug("Resource cleanup completed")
            
        except Exception as e:
            self.logger.debug(f"Resource cleanup failed: {e}")