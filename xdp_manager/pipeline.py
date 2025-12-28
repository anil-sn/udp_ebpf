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
from .bpf import BPFMapManager
from .allowlist import AllowlistManager
from .display import DisplayManager
from .system_tuning import SystemTuner
from .interface_management import InterfaceManager

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
        self.system_tuner = SystemTuner(self.runner, self.logger)
        self.interface_manager = InterfaceManager(self.runner, self.logger)
        
        # Pipeline process tracking (for vxlan_loader)
        self._pipeline_process = None
        
        # Load configuration
        self.config.load_config()
        
    def start(self, interface: Optional[str] = None, force: bool = False) -> bool:
        """Start XDP pipeline following repomix-output.xml patterns exactly"""
        try:
            self.logger.info("Starting XDP pipeline deployment...")
            
            # Determine target interface first 
            target_interface = interface or self.config.pipeline_config.ingress_interface
            if not target_interface:
                target_interface = self.network.get_recommended_interface()
                if not target_interface:
                    self.logger.error("No suitable network interface found")
                    return False
            
            # Check for existing processes first (matches bash implementation exactly)
            import subprocess
            self.logger.info(f"Checking for existing vxlan_loader processes on {target_interface}...")
            result = subprocess.run(
                ['pgrep', '-f', f'vxlan_loader.*-i.*{target_interface}'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0 and not force:
                pids = result.stdout.strip().split('\n')
                self.logger.error(f"Pipeline already running on {target_interface} (PID: {pids[0]})")
                self.logger.info("Use --force to restart or stop first")
                return False
            elif result.returncode == 0 and force:
                pids = result.stdout.strip().split('\n')
                self.logger.info(f"Force restart requested, existing process PID: {pids[0]}")
            else:
                self.logger.info("No existing vxlan_loader processes found")
            
            # Force cleanup existing XDP programs (matches bash approach exactly)
            self.logger.info("Cleaning any orphaned XDP programs...")
            try:
                cleanup_result = subprocess.run([
                    'sudo', 'ip', 'link', 'set', target_interface, 'xdp', 'off'
                ], capture_output=True, text=True)
                if cleanup_result.returncode == 0:
                    self.logger.debug(f"XDP cleanup successful on {target_interface}")
                else:
                    self.logger.debug(f"XDP cleanup: {cleanup_result.stderr.strip()}")
            except Exception as e:
                self.logger.debug(f"XDP cleanup failed: {e}")
            
            # Get config for vxlan_loader parameters
            config = self.config.get_config()
            pipeline_cfg = config.pipeline_config
            
            # Log configuration being used
            self.logger.info(f"Configuration: ingress={target_interface}, egress={pipeline_cfg.egress_interface}")
            self.logger.info(f"NAT target: {getattr(pipeline_cfg, 'nat_target_ip', '172.30.82.50')}:{getattr(pipeline_cfg, 'nat_target_port', 8081)}")
            
            # Change to the main directory (matches bash: cd "$SCRIPT_DIR")
            import os
            original_cwd = os.getcwd()
            
            # Build vxlan_loader command (matches bash implementation exactly)
            nat_ip = getattr(pipeline_cfg, 'nat_target_ip', '172.30.82.50')
            nat_port = getattr(pipeline_cfg, 'nat_target_port', 8081)
            source_port = getattr(pipeline_cfg, 'source_port', 31765)
            stats_interval = getattr(pipeline_cfg, 'statistics_interval', 5)
            
            cmd = [
                'sudo', 'src/vxlan_loader',  # Binary is in src/ directory
                '-i', target_interface,
                '-t', pipeline_cfg.egress_interface,
                '-a', str(nat_ip),
                '-p', str(nat_port), 
                '-s', str(source_port),
                '-I', str(stats_interval)
            ]
            
            # Log the exact command being executed
            self.logger.info(f"Executing command: {' '.join(cmd)}")
            
            # Start vxlan_loader with nohup (matches bash exactly)
            log_file = f"pipeline_{target_interface}.log"
            self.logger.info(f"Launching vxlan_loader, log: {log_file}")
            
            # Use nohup equivalent with proper redirection (matches bash nohup)
            with open(os.devnull, 'r') as devnull:
                with open(log_file, 'w') as f:
                    process = subprocess.Popen(
                        cmd,
                        stdin=devnull,
                        stdout=f,
                        stderr=subprocess.STDOUT,
                        cwd=original_cwd,  # Run from main directory
                        start_new_session=True  # Equivalent to nohup
                    )
            
            # Give time for startup (matches bash sleep 3 exactly)
            import time
            self.logger.info("Waiting 3 seconds for vxlan_loader startup...")
            time.sleep(3)
            
            # Verify startup with specific pattern match (matches bash exactly)
            self.logger.info(f"Verifying vxlan_loader startup on {target_interface}...")
            result = subprocess.run(
                ['pgrep', '-f', f'vxlan_loader.*-i.*{target_interface}'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                new_pid = result.stdout.strip().split('\n')[0]
                self.logger.info(f"SUCCESS: Pipeline started (PID: {new_pid})")
                self.logger.info(f"Log file: {log_file}")
                
                # Check if process is actually running properly
                ps_result = subprocess.run(
                    ['ps', '-p', new_pid, '-o', 'pid,ppid,cmd'],
                    capture_output=True, text=True
                )
                if ps_result.returncode == 0:
                    self.logger.debug(f"Process details: {ps_result.stdout.strip()}")
                else:
                    self.logger.warning(f"Could not get process details for PID {new_pid}")
                
                # Load IP allowlist after successful pipeline start (matches bash)
                self.logger.info("Loading IP allowlist...")
                allowlist_file = "ip_allowlist.json"  # bash looks in current dir
                
                if os.path.exists(allowlist_file):
                    # Give BPF maps time to fully initialize (matches bash sleep 2)
                    time.sleep(2)
                    self.logger.info("Attempting to load IPs from allowlist...")
                    
                    try:
                        # Use load_ip_allowlist.py from current directory (matches bash exactly)
                        subprocess.run([
                            'sudo', 'python3', 'load_ip_allowlist.py', allowlist_file
                        ], check=True, cwd=original_cwd)
                        self.logger.info("IP allowlist loaded successfully")
                    except subprocess.CalledProcessError:
                        self.logger.warning("Warning: Failed to load IP allowlist - check BPF program status")
                else:
                    self.logger.warning("Warning: ip_allowlist.json not found")
                
                # Allow time for vxlan_loader to fully initialize (matches bash sleep 3)
                self.logger.info("Waiting for BPF map initialization...")
                time.sleep(3)
                
                return True
            else:
                self.logger.error("Failed to start vxlan_loader process")
                # Check if log file has error details
                try:
                    with open(log_file, 'r') as f:
                        log_contents = f.read().strip()
                        if log_contents:
                            self.logger.error(f"vxlan_loader error output: {log_contents}")
                        else:
                            self.logger.error("No output in log file - process may have failed to start")
                except FileNotFoundError:
                    self.logger.error(f"Log file {log_file} not found")
                except Exception as e:
                    self.logger.error(f"Could not read log file: {e}")
                
                # Additional debugging - check if binary exists and is executable
                binary_path = "src/vxlan_loader"
                import os
                if not os.path.exists(binary_path):
                    self.logger.error(f"Binary not found: {binary_path}")
                elif not os.access(binary_path, os.X_OK):
                    self.logger.error(f"Binary not executable: {binary_path}")
                else:
                    self.logger.error(f"Binary exists and is executable: {binary_path}")
                
                return False
                
        except Exception as e:
            self.logger.error(f"Pipeline start failed: {e}")
            return False

    def stop(self, interface: Optional[str] = None, force: bool = False, cleanup: bool = True) -> bool:
        """Stop XDP pipeline following repomix-output.xml patterns exactly"""
        try:
            self.logger.info("Stopping XDP pipeline...")
            
            import subprocess
            import time
            
            # Kill vxlan_loader process if exists (matches bash exactly)
            result = subprocess.run(['pgrep', '-f', 'vxlan_loader'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info("Stopping vxlan_loader...")
                
                # TERM signal first (matches bash)
                subprocess.run(['sudo', 'pkill', '-TERM', '-f', 'vxlan_loader'], 
                             capture_output=True)
                
                # Wait loop (matches bash: for i in {1..3})
                for i in range(1, 4):  # 1,2,3
                    result = subprocess.run(['pgrep', '-f', 'vxlan_loader'],
                                          capture_output=True)
                    if result.returncode != 0:  # No processes found
                        break
                    time.sleep(1)
                
                # Force kill (matches bash)
                subprocess.run(['sudo', 'pkill', '-KILL', '-f', 'vxlan_loader'], 
                             capture_output=True)
                self.logger.info("✓ vxlan_loader stopped")
            
            # Kill packet_injector process if exists (matches bash exactly)
            result = subprocess.run(['pgrep', '-f', 'packet_injector'],
                                  capture_output=True, text=True)
                                  
            if result.returncode == 0:
                self.logger.info("Stopping packet_injector...")
                
                # TERM signal first
                subprocess.run(['sudo', 'pkill', '-TERM', '-f', 'packet_injector'],
                             capture_output=True)
                
                # Wait loop
                for i in range(1, 4):  # 1,2,3
                    result = subprocess.run(['pgrep', '-f', 'packet_injector'],
                                          capture_output=True)
                    if result.returncode != 0:  # No processes found
                        break
                    time.sleep(1)
                
                # Force kill
                subprocess.run(['sudo', 'pkill', '-KILL', '-f', 'packet_injector'],
                             capture_output=True)
                self.logger.info("✓ packet_injector stopped")
            
            # Clean interface using xdpgeneric (matches bash exactly)
            config = self.config.get_config()
            target_interface = interface or config.pipeline_config.ingress_interface
            
            if target_interface:
                # Use xdpgeneric off as in bash: sudo ip link set "$INTERFACE" xdpgeneric off
                subprocess.run([
                    'sudo', 'ip', 'link', 'set', target_interface, 'xdpgeneric', 'off'
                ], capture_output=True)
                self.logger.info(f"Cleaned XDP from {target_interface}")
            
            # Clean up BPF resources (matches bash cleanup_bpf call)
            if cleanup:
                self._cleanup_bpf_resources(target_interface)
            
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
        """Get current pipeline operational status (matches bash approach)"""
        try:
            import subprocess
            
            # Method 1: Check for vxlan_loader process (matches bash approach exactly)
            result = subprocess.run(['pgrep', '-f', 'vxlan_loader'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                # Process is running - this is primary indicator
                self.logger.debug("vxlan_loader process detected - pipeline running")
                return PipelineStatus.RUNNING
            
            # Method 2: Check for XDP attachment (secondary verification) 
            if self._is_xdp_loaded():
                self.logger.debug("XDP program detected but no vxlan_loader process")
                # Maps verification is optional - don't fail on map errors
                try:
                    self._verify_maps()  # Log any issues but don't fail
                except Exception as e:
                    self.logger.debug(f"Map verification error (non-critical): {e}")
                
                return PipelineStatus.RUNNING  # Consider running if XDP is attached
            
            # No process and no XDP attachment
            self.logger.debug("No vxlan_loader process or XDP programs detected")
            return PipelineStatus.STOPPED
                
        except Exception as e:
            self.logger.error(f"Status check failed: {e}")
            return PipelineStatus.UNKNOWN
    
    def is_running(self) -> bool:
        """Check if pipeline is currently running"""
        try:
            # Check if vxlan_loader process is running
            if hasattr(self, '_pipeline_process') and self._pipeline_process:
                if self._pipeline_process.poll() is None:
                    return True
            
            # Fallback: check XDP attachment status
            return self.get_status() == PipelineStatus.RUNNING
            
        except Exception:
            return False
    
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
        """Deploy compiled BPF program to network interface using the working vxlan_loader method"""
        try:
            self.logger.info(f"Deploying BPF program to interface {interface}")
            
            # Check if we have the compiled vxlan_loader (working solution)
            from pathlib import Path
            src_path = Path(program_file).parent
            vxlan_loader = src_path / "vxlan_loader"
            
            if vxlan_loader.exists():
                self.logger.info("Using compiled vxlan_loader for deployment (matches working solution)")
                
                # Get target interface from config
                target_interface = self.config.pipeline_config.egress_interface or "ens6"
                
                # Use the working vxlan_loader approach
                import os
                original_cwd = os.getcwd()
                
                try:
                    # Change to src directory where vxlan_loader expects to find files
                    os.chdir(src_path)
                    
                    # Run vxlan_loader with the same parameters as working solution
                    deploy_cmd = [
                        'sudo', './vxlan_loader',
                        '-i', interface,                              # ingress interface
                        '-t', target_interface,                       # target interface
                        '-a', self.config.pipeline_config.nat_target_ip,      # NAT target IP
                        '-p', str(self.config.pipeline_config.nat_target_port), # NAT target port
                        '-s', str(self.config.pipeline_config.source_port),     # NAT source port
                        '-I', str(self.config.pipeline_config.statistics_interval), # stats interval
                        '-v'  # verbose mode
                    ]
                    
                    self.logger.info(f"Deploying with command: {' '.join(deploy_cmd)}")
                    
                    # Start vxlan_loader in background (as per working solution)
                    import subprocess
                    process = subprocess.Popen(
                        deploy_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # Give it time to initialize
                    import time
                    time.sleep(2)
                    
                    # Check if process started successfully
                    if process.poll() is None:
                        # Process is running - success
                        self.logger.info(f"XDP pipeline deployed successfully on {interface}")
                        
                        # Store process handle for cleanup
                        self._pipeline_process = process
                        
                        # Verify XDP attachment
                        time.sleep(1)
                        attached = self.network.get_interface(interface)
                        if attached and getattr(attached, 'xdp_attached', False):
                            self.logger.info(f"Verified: XDP program is attached to {interface}")
                            return True
                        else:
                            self.logger.warning(f"XDP program may not be properly attached to {interface}")
                            return True  # Continue anyway, as process started successfully
                    
                    else:
                        # Process exited immediately - error
                        stdout, stderr = process.communicate()
                        self.logger.error(f"vxlan_loader failed to start:")
                        if stdout:
                            self.logger.error(f"stdout: {stdout}")
                        if stderr:
                            self.logger.error(f"stderr: {stderr}")
                        return False
                        
                finally:
                    os.chdir(original_cwd)
            
            else:
                # Fallback to bpftool if vxlan_loader not available
                self.logger.warning("vxlan_loader not found, using bpftool fallback")
                return self.network.attach_xdp(interface, program_file)
                
        except Exception as e:
            self.logger.error(f"Failed to deploy BPF program: {e}")
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
            if result.returncode != 0:
                self.logger.debug("bpftool command failed")
                return False
            
            self.logger.debug(f"bpftool output: {repr(result.stdout)}")
            
            # Parse output to check if XDP programs are actually attached
            # Look for lines with interface names after "xdp:" section
            output_lines = result.stdout.strip().split('\n')
            in_xdp_section = False
            
            for line in output_lines:
                line = line.strip()
                self.logger.debug(f"Processing line: '{line}', in_xdp_section: {in_xdp_section}")
                
                if line == 'xdp:':
                    in_xdp_section = True
                    continue
                elif line.endswith(':'):  # New section (tc:, flow_dissector:, etc.)
                    in_xdp_section = False
                    continue
                elif in_xdp_section and line and not line.isspace():
                    # Found an actual XDP attachment
                    self.logger.info(f"Found XDP attachment: {line}")
                    return True
            
            self.logger.info("No XDP programs currently attached")
            return False
        except Exception as e:
            self.logger.error(f"Error checking XDP status: {e}")
            return False
    
    def _verify_maps(self) -> bool:
        """Verify required BPF maps exist and are accessible (graceful fallback)"""
        try:
            map_validation = self.bpf_maps.validate_maps()
            required_maps = ['stats_map', 'ip_allowlist_lpm']
            
            missing_maps = []
            for map_name in required_maps:
                if not map_validation.get(map_name, False):
                    missing_maps.append(map_name)
            
            if missing_maps:
                self.logger.debug(f"BPF maps not found: {missing_maps} (may be expected when stopped)")
                return False
            
            self.logger.debug("All required BPF maps verified successfully")
            return True
            
        except Exception as e:
            # Log but don't fail - maps may not exist when pipeline is stopped
            self.logger.debug(f"Map verification failed (non-critical): {e}")
            return False
    
    def _check_running_processes(self, interface: Optional[str], force: bool) -> bool:
        """Check for running vxlan_loader processes (matches bash behavior)"""
        try:
            import subprocess
            target_interface = interface or self.config.pipeline_config.ingress_interface
            
            # Check for existing vxlan_loader process
            result = subprocess.run(
                ['pgrep', '-f', f'vxlan_loader.*-i.*{target_interface}'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:  # Process found
                pids = result.stdout.strip().split('\n')
                if not force:
                    self.logger.error(f"Pipeline already running on {target_interface} (PID: {pids[0]})")
                    self.logger.info("Use --force to restart or stop first")
                    return False
                else:
                    self.logger.info(f"Force restart requested, will stop existing process (PID: {pids[0]})")
                    
            return True
            
        except Exception as e:
            self.logger.warning(f"Process check failed: {e}")
            return True  # Continue if check fails
    
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
    
    def _cleanup_bpf_resources(self, interface: Optional[str] = None) -> None:
        """Clean up BPF resources following bash cleanup_bpf function exactly"""
        import subprocess
        
        # Use detected interface if not provided
        if not interface:
            interface = self.config.pipeline_config.ingress_interface or "ens5"
        
        # 1. Kill processes first to stop new activity (matches bash exactly)
        subprocess.run(['sudo', 'pkill', '-KILL', '-f', 'vxlan_loader'], 
                      capture_output=True, check=False)
        
        # 2. Detach XDP from ALL interfaces (matches bash exactly)
        self.logger.info("Cleaning up XDP programs...")
        egress_interface = getattr(self.config.pipeline_config, 'egress_interface', 'ens6')
        
        try:
            # ip link set <interface> xdp off (matches bash exactly)
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'xdp', 'off'],
                          capture_output=True, check=False)
            subprocess.run(['sudo', 'ip', 'link', 'set', egress_interface, 'xdp', 'off'],
                          capture_output=True, check=False)
        except Exception as e:
            self.logger.debug(f"Failed to remove xdp: {e}")
        
        # 3. CRITICAL: Force remove ALL vxlan_pipeline_main programs by ID (matches bash exactly)
        try:
            result = subprocess.run(['sudo', 'bpftool', 'prog', 'list'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                prog_ids = []
                for line in lines:
                    if 'vxlan_pipeline_main' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            prog_id = parts[0].strip()
                            if prog_id:
                                prog_ids.append(prog_id)
                
                for prog_id in prog_ids:
                    self.logger.info(f"Force removing XDP program ID: {prog_id}")
                    # Try to detach from both interfaces (matches bash)
                    subprocess.run(['sudo', 'bpftool', 'prog', 'detach', 'xdp', 
                                  'id', prog_id, 'dev', interface], 
                                 capture_output=True, check=False)
                    subprocess.run(['sudo', 'bpftool', 'prog', 'detach', 'xdp', 
                                  'id', prog_id, 'dev', egress_interface], 
                                 capture_output=True, check=False)
                
                if prog_ids:
                    self.logger.info("✓ All XDP programs successfully removed")
        except Exception as e:
            self.logger.debug(f"BPF program cleanup failed: {e}")
            
        # 3. Force remove any tc programs (matches bash tc cleanup)
        try:
            # Remove clsact qdisc which removes attached programs (matches bash)
            subprocess.run([
                'sudo', 'tc', 'qdisc', 'del', 'dev', interface, 'clsact'
            ], capture_output=True, check=False)
        except:
            pass  # May not exist
            
        # 4. Clean up pinned maps (matches bash exactly)
        self.logger.info("Cleaning pinned BPF maps...")
        bpf_maps = [
            "/sys/fs/bpf/vxlan_stats_map",
            "/sys/fs/bpf/vxlan_nat_map", 
            "/sys/fs/bpf/vxlan_redirect_map",
            "/sys/fs/bpf/vxlan_interface_map",
            "/sys/fs/bpf/vxlan_ip_allowlist",
            "/sys/fs/bpf/vxlan_packet_ringbuf"
        ]
        
        for map_path in bpf_maps:
            subprocess.run(['sudo', 'rm', '-f', map_path], 
                         capture_output=True, check=False)
        
        # Remove pinned BPF objects with find (matches bash exactly)
        if os.path.exists("/sys/fs/bpf"):
            find_patterns = ['*vxlan*', '*nat_map*', '*stats_map*', '*ip_allowlist*', '*packet_ringbuf*']
            for pattern in find_patterns:
                subprocess.run(['sudo', 'find', '/sys/fs/bpf', '-name', pattern, '-delete'], 
                             capture_output=True, check=False)
        
        # Wait for kernel cleanup and garbage collection (matches bash)
        import time
        time.sleep(3)
        
        # Verify cleanup worked (matches bash verification)
        try:
            result = subprocess.run(['sudo', 'bpftool', 'prog', 'list'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                remaining = len([line for line in result.stdout.split('\n') 
                               if 'vxlan_pipeline_main' in line])
                if remaining > 0:
                    self.logger.warning(f"Warning: {remaining} XDP programs still loaded")
                    self.logger.warning("Manual cleanup may be needed: sudo bpftool prog list | grep vxlan")
                else:
                    self.logger.info("✓ All XDP programs successfully removed")
        except:
            pass
            
        self.logger.info(f"BPF cleanup completed for {interface}")

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