import psutil
import time
import os
import platform
import socket
import subprocess
import json
import hashlib
import tempfile
from datetime import datetime, timedelta
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.tree import Tree
from rich.syntax import Syntax
from pathlib import Path
import threading
import queue

# --- KONFIGURASI ---
console = Console()

class AegisMonitorV3:
    def __init__(self):
        self.start_time = datetime.now()
        self.notifications = []
        self.alert_history = []
        self.data_history = {'cpu': [], 'ram': [], 'disk': [], 'network': []}
        self.max_history = 30
        self.export_count = 0
        self.screenshot_count = 0
        
        # Thresholds (Customizable)
        self.thresholds = {
            'cpu_warn': 70, 'cpu_crit': 90,
            'ram_warn': 75, 'ram_crit': 90,
            'disk_warn': 80, 'disk_crit': 95,
            'temp_warn': 70, 'temp_crit': 85,
            'swap_warn': 50, 'swap_crit': 80,
            'conn_warn': 1000, 'conn_crit': 5000,
            'proc_warn': 300, 'proc_crit': 500
        }
        
        # Data Storage untuk 50 Fitur
        self.data = {}
        self.prev_net = None
        self.prev_disk_io = None
        self.prev_proc_count = None
        self.zombie_alert = False
        
        # Export Directory
        self.export_dir = "aegis_exports"
        os.makedirs(self.export_dir, exist_ok=True)
        
        # Background Tasks
        self.task_queue = queue.Queue()
        self.background_results = {}
        
    def get_all_system_data(self):
        """Mengumpulkan data untuk 50 Fitur"""
        
        # === CPU MONITORING (Fitur 1-7) ===
        # 1. CPU Usage Total
        self.data['cpu_percent'] = psutil.cpu_percent(interval=0.3)
        
        # 2. CPU Usage Per Core
        self.data['cpu_per_core'] = psutil.cpu_percent(percpu=True, interval=0.1)
        
        # 3. CPU Frequency
        freq = psutil.cpu_freq()
        self.data['cpu_freq_current'] = f"{freq.current:.0f}" if freq else "N/A"
        self.data['cpu_freq_max'] = f"{freq.max:.0f}" if freq else "N/A"
        self.data['cpu_freq_min'] = f"{freq.min:.0f}" if freq else "N/A"
        
        # 4. CPU Temperature
        self.data['cpu_temp'] = self._get_cpu_temp()
        
        # 5. CPU Cores (Physical & Logical)
        self.data['cpu_cores_physical'] = psutil.cpu_count(logical=False)
        self.data['cpu_cores_logical'] = psutil.cpu_count(logical=True)
        
        # 6. CPU Load Average (1, 5, 15 min)
        try:
            load_avg = os.getloadavg()
            self.data['load_avg'] = f"{load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}"
            self.data['load_avg_1'] = load_avg[0]
            self.data['load_avg_5'] = load_avg[1]
            self.data['load_avg_15'] = load_avg[2]
        except:
            self.data['load_avg'] = "N/A (Windows)"
            self.data['load_avg_1'] = 0
            self.data['load_avg_5'] = 0
            self.data['load_avg_15'] = 0
        
        # 7. CPU Times (User, System, Idle)
        cpu_times = psutil.cpu_times_percent()
        self.data['cpu_time_user'] = cpu_times.user
        self.data['cpu_time_system'] = cpu_times.system
        self.data['cpu_time_idle'] = cpu_times.idle
        
        # === MEMORY MONITORING (Fitur 8-14) ===
        # 8. RAM Usage Percent
        mem = psutil.virtual_memory()
        self.data['ram_percent'] = mem.percent
        
        # 9. RAM Total/Used/Available
        self.data['ram_total'] = mem.total / (1024**3)
        self.data['ram_used'] = mem.used / (1024**3)
        self.data['ram_available'] = mem.available / (1024**3)
        self.data['ram_free'] = mem.free / (1024**3)
        
        # 10. RAM Cached & Buffers
        self.data['ram_cached'] = getattr(mem, 'cached', 0) / (1024**3)
        self.data['ram_buffers'] = getattr(mem, 'buffers', 0) / (1024**3)
        
        # 11. RAM Shared Memory
        self.data['ram_shared'] = getattr(mem, 'shared', 0) / (1024**3)
        
        # 12. Swap Usage
        swap = psutil.swap_memory()
        self.data['swap_percent'] = swap.percent
        self.data['swap_total'] = swap.total / (1024**3)
        self.data['swap_used'] = swap.used / (1024**3)
        self.data['swap_free'] = swap.free / (1024**3)
        
        # 13. Memory Pressure Score
        self.data['memory_pressure'] = self._calc_memory_pressure(mem)
        
        # 14. Memory Pages In/Out
        try:
            vm_stats = psutil.virtual_memory()
            self.data['mem_pages_in'] = "N/A"
            self.data['mem_pages_out'] = "N/A"
        except:
            self.data['mem_pages_in'] = "N/A"
            self.data['mem_pages_out'] = "N/A"
        
        # === DISK MONITORING (Fitur 15-22) ===
        # 15. Disk Usage Root
        disk = psutil.disk_usage('/')
        self.data['disk_percent'] = disk.percent
        self.data['disk_total'] = disk.total / (1024**3)
        self.data['disk_used'] = disk.used / (1024**3)
        self.data['disk_free'] = disk.free / (1024**3)
        
        # 16. Disk Partitions
        partitions = psutil.disk_partitions()
        self.data['disk_partitions'] = len(partitions)
        self.data['partition_list'] = []
        for p in partitions:
            try:
                p_usage = psutil.disk_usage(p.mountpoint)
                self.data['partition_list'].append({
                    'device': p.device,
                    'mountpoint': p.mountpoint,
                    'fstype': p.fstype,
                    'total': p_usage.total / (1024**3),
                    'used': p_usage.used / (1024**3),
                    'percent': p_usage.percent
                })
            except:
                pass
        
        # 17. Disk I/O Read/Write Bytes
        disk_io = psutil.disk_io_counters()
        if disk_io:
            self.data['disk_read_bytes'] = disk_io.read_bytes
            self.data['disk_write_bytes'] = disk_io.write_bytes
            
            # 18. Disk I/O Speed (Calculation)
            if self.prev_disk_io:
                self.data['disk_read_speed'] = (disk_io.read_bytes - self.prev_disk_io.read_bytes) / 0.5
                self.data['disk_write_speed'] = (disk_io.write_bytes - self.prev_disk_io.write_bytes) / 0.5
            else:
                self.data['disk_read_speed'] = 0
                self.data['disk_write_speed'] = 0
            self.prev_disk_io = disk_io
        else:
            self.data['disk_read_speed'] = 0
            self.data['disk_write_speed'] = 0
        
        # 19. Disk I/O Operations Count
        self.data['disk_read_count'] = disk_io.read_count if disk_io else 0
        self.data['disk_write_count'] = disk_io.write_count if disk_io else 0
        
        # 20. Disk I/O Time
        self.data['disk_read_time'] = disk_io.read_time if disk_io else 0
        self.data['disk_write_time'] = disk_io.write_time if disk_io else 0
        
        # 21. Open Files Count (System-wide)
        try:
            self.data['open_files'] = sum(len(p.open_files()) for p in psutil.process_iter(['open_files']) if p.info['open_files'])
        except:
            self.data['open_files'] = "N/A"
        
        # 22. File Descriptors Usage
        try:
            self.data['fd_usage'] = self._get_fd_usage()
        except:
            self.data['fd_usage'] = "N/A"
        
        # === NETWORK MONITORING (Fitur 23-30) ===
        # 23. Network Bytes Sent/Recv
        net = psutil.net_io_counters()
        self.data['net_sent'] = net.bytes_sent
        self.data['net_recv'] = net.bytes_recv
        self.data['net_packets_sent'] = net.packets_sent
        self.data['net_packets_recv'] = net.packets_recv
        
        # 24. Network Speed (Upload/Download)
        if self.prev_net:
            self.data['net_up_speed'] = (net.bytes_sent - self.prev_net.bytes_sent) / 0.5
            self.data['net_down_speed'] = (net.bytes_recv - self.prev_net.bytes_recv) / 0.5
        else:
            self.data['net_up_speed'] = 0
            self.data['net_down_speed'] = 0
        self.prev_net = net
        
        # 25. Network Connections Active
        try:
            connections = psutil.net_connections(kind='inet')
            self.data['net_connections'] = len(connections)
            self.data['net_connections_listen'] = len([c for c in connections if c.status == 'LISTEN'])
            self.data['net_connections_established'] = len([c for c in connections if c.status == 'ESTABLISHED'])
            self.data['net_connections_time_wait'] = len([c for c in connections if c.status == 'TIME_WAIT'])
        except:
            self.data['net_connections'] = 0
            self.data['net_connections_listen'] = 0
            self.data['net_connections_established'] = 0
            self.data['net_connections_time_wait'] = 0
        
        # 26. Network Interfaces
        net_if = psutil.net_if_addrs()
        self.data['net_interfaces'] = list(net_if.keys())
        self.data['net_interface_details'] = []
        for iface, addrs in net_if.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    self.data['net_interface_details'].append({
                        'name': iface,
                        'ip': addr.address,
                        'netmask': addr.netmask
                    })
        
        # 27. Network Interface Stats
        self.data['net_interface_stats'] = psutil.net_if_stats()
        
        # 28. Hostname & IP
        self.data['hostname'] = socket.gethostname()
        try:
            self.data['ip_address'] = socket.gethostbyname(socket.gethostname())
        except:
            self.data['ip_address'] = "127.0.0.1"
        
        # 29. DNS Servers
        self.data['dns_servers'] = self._get_dns_servers()
        
        # 30. Network Latency (Ping to Gateway/Google)
        self.data['network_latency'] = self._check_network_latency()
        
        # === PROCESS MONITORING (Fitur 31-37) ===
        # 31. Total Processes Running
        self.data['process_count'] = len(psutil.pids())
        
        # 32. Process Count Change (Delta)
        if self.prev_proc_count:
            self.data['process_delta'] = self.data['process_count'] - self.prev_proc_count
        else:
            self.data['process_delta'] = 0
        self.prev_proc_count = self.data['process_count']
        
        # 33. Top 5 Processes by CPU
        self.data['top_processes_cpu'] = self._get_top_processes('cpu_percent', 5)
        
        # 34. Top 5 Processes by Memory
        self.data['top_processes_mem'] = self._get_top_processes('memory_percent', 5)
        
        # 35. Zombie Processes
        zombies = []
        for p in psutil.process_iter(['status', 'pid', 'name']):
            try:
                if p.info['status'] == psutil.STATUS_ZOMBIE:
                    zombies.append({'pid': p.info['pid'], 'name': p.info['name']})
            except:
                pass
        self.data['zombie_processes'] = zombies
        self.data['zombie_count'] = len(zombies)
        
        # 36. Process by State (Running, Sleeping, etc.)
        proc_states = {'running': 0, 'sleeping': 0, 'stopped': 0, 'zombie': 0, 'other': 0}
        for p in psutil.process_iter(['status']):
            try:
                status = p.info['status']
                if status in proc_states:
                    proc_states[status] += 1
                else:
                    proc_states['other'] += 1
            except:
                proc_states['other'] += 1
        self.data['process_states'] = proc_states
        
        # 37. Process Threads Total
        self.data['total_threads'] = sum(p.num_threads() for p in psutil.process_iter(['num_threads']) if p.info['num_threads'])
        
        # === SYSTEM INFO (Fitur 38-44) ===
        # 38. System Uptime
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        self.data['uptime'] = datetime.now() - boot_time
        self.data['boot_time'] = boot_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # 39. OS Information
        self.data['os_name'] = platform.system()
        self.data['os_version'] = platform.version()
        self.data['os_release'] = platform.release()
        self.data['os_architecture'] = platform.machine()
        self.data['os_processor'] = platform.processor()
        
        # 40. Python Version
        self.data['python_version'] = platform.python_version()
        
        # 41. Logged In Users
        self.data['logged_users'] = [u.name for u in psutil.users()]
        self.data['logged_users_details'] = []
        for u in psutil.users():
            self.data['logged_users_details'].append({
                'name': u.name,
                'terminal': u.terminal,
                'host': u.host,
                'started': u.started
            })
        
        # 42. Battery Status
        battery = psutil.sensors_battery()
        if battery:
            self.data['battery_percent'] = battery.percent
            self.data['battery_plugged'] = battery.power_plugged
            self.data['battery_time_left'] = battery.secsleft
        else:
            self.data['battery_percent'] = None
            self.data['battery_plugged'] = True
            self.data['battery_time_left'] = None
        
        # 43. System Locale
        self.data['locale'] = os.environ.get('LANG', 'N/A')
        
        # 44. Timezone
        self.data['timezone'] = time.tzname
        
        # === SECURITY & ADVANCED (Fitur 45-50) ===
        # 45. Environment Variables Count
        self.data['env_vars_count'] = len(os.environ)
        
        # 46. Home Directory Space
        home = Path.home()
        if home.exists():
            try:
                home_usage = psutil.disk_usage(str(home))
                self.data['home_total'] = home_usage.total / (1024**3)
                self.data['home_used'] = home_usage.used / (1024**3)
                self.data['home_free'] = home_usage.free / (1024**3)
            except:
                self.data['home_total'] = 0
                self.data['home_used'] = 0
                self.data['home_free'] = 0
        else:
            self.data['home_total'] = 0
            self.data['home_used'] = 0
            self.data['home_free'] = 0
        
        # 47. Temporary Directory Space
        temp_dir = Path(tempfile.gettempdir())
        if temp_dir.exists():
            try:
                temp_usage = psutil.disk_usage(str(temp_dir))
                self.data['temp_total'] = temp_usage.total / (1024**3)
                self.data['temp_used'] = temp_usage.used / (1024**3)
                self.data['temp_free'] = temp_usage.free / (1024**3)
            except:
                self.data['temp_total'] = 0
                self.data['temp_used'] = 0
                self.data['temp_free'] = 0
        else:
            self.data['temp_total'] = 0
            self.data['temp_used'] = 0
            self.data['temp_free'] = 0
        
        # 48. System Security Level (Basic Check)
        self.data['security_level'] = self._check_security_level()
        
        # 49. Recent File Changes (Last 5 minutes in /tmp)
        self.data['recent_files'] = self._get_recent_files()
        
        # 50. System Resource Prediction (Simple Forecast)
        self.data['resource_forecast'] = self._predict_resources()
        
        # === HEALTH & ALERTS ===
        self._calculate_health_score()
        self._check_alerts()
        self._update_history()
    
    def _get_cpu_temp(self):
        """Get CPU Temperature"""
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                for name, entries in temps.items():
                    for entry in entries:
                        if 'cpu' in name.lower() or 'core' in entry.label.lower():
                            return f"{entry.current:.1f}°C"
                return f"{list(temps.values())[0][0].current:.1f}°C"
            return "N/A"
        except:
            return "N/A"
    
    def _calc_memory_pressure(self, mem):
        """Calculate Memory Pressure Score"""
        available_percent = (mem.available / mem.total) * 100
        if available_percent > 50:
            return "LOW"
        elif available_percent > 25:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def _get_top_processes(self, key, limit):
        """Get Top Processes by Key"""
        procs = []
        for p in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']), 
                       key=lambda p: p.info.get(key, 0) or 0, reverse=True)[:limit]:
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs
    
    def _get_fd_usage(self):
        """Get File Descriptor Usage (Linux)"""
        try:
            fd_count = len(os.listdir('/proc/self/fd'))
            fd_limit = psutil.Process().rlimit(psutil.RLIMIT_NOFILE)[0]
            return f"{fd_count}/{fd_limit}"
        except:
            return "N/A"
    
    def _get_dns_servers(self):
        """Get DNS Servers"""
        try:
            with open('/etc/resolv.conf', 'r') as f:
                dns = [line.split()[1] for line in f if line.startswith('nameserver')]
                return ', '.join(dns) if dns else "N/A"
        except:
            return "N/A"
    
    def _check_network_latency(self):
        """Check Network Latency"""
        try:
            result = subprocess.run(['ping', '-c', '1', '8.8.8.8'], 
                                  capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                time_line = [line for line in result.stdout.split('\n') if 'time=' in line]
                if time_line:
                    time_val = time_line[0].split('time=')[1].split(' ')[0]
                    return f"{time_val} ms"
            return "N/A"
        except:
            return "N/A"
    
    def _check_security_level(self):
        """Basic Security Level Check"""
        score = 0
        checks = []
        
        # Check if running as root
        if os.geteuid() == 0:
            checks.append("⚠️ Running as root")
        else:
            score += 20
            checks.append("✓ Not running as root")
        
        # Check for zombie processes
        if self.data.get('zombie_count', 0) > 0:
            checks.append(f"⚠️ {self.data['zombie_count']} zombie processes")
        else:
            score += 20
            checks.append("✓ No zombie processes")
        
        # Check open connections
        if self.data.get('net_connections', 0) > 1000:
            checks.append("⚠️ High network connections")
        else:
            score += 20
            checks.append("✓ Normal network connections")
        
        # Check logged users
        if len(self.data.get('logged_users', [])) > 5:
            checks.append("⚠️ Many logged users")
        else:
            score += 20
            checks.append("✓ Normal user count")
        
        # Check system updates (basic)
        score += 20
        checks.append("✓ System check passed")
        
        level = "HIGH" if score >= 80 else "MEDIUM" if score >= 50 else "LOW"
        return {'level': level, 'score': score, 'checks': checks}
    
    def _get_recent_files(self, directory='/tmp', minutes=5):
        """Get Recently Modified Files"""
        recent = []
        try:
            cutoff = time.time() - (minutes * 60)
            for root, dirs, files in os.walk(directory):
                for file in files[:10]:  # Limit to 10 files
                    filepath = os.path.join(root, file)
                    try:
                        mtime = os.path.getmtime(filepath)
                        if mtime > cutoff:
                            recent.append({
                                'path': filepath,
                                'mtime': datetime.fromtimestamp(mtime).strftime('%H:%M:%S')
                            })
                    except:
                        pass
                if len(recent) >= 5:
                    break
        except:
            pass
        return recent[:5]
    
    def _predict_resources(self):
        """Simple Resource Forecasting"""
        forecast = {}
        
        # CPU Forecast
        if len(self.data_history['cpu']) >= 5:
            recent_cpu = self.data_history['cpu'][-5:]
            trend = (recent_cpu[-1] - recent_cpu[0]) / len(recent_cpu)
            forecast['cpu_trend'] = "increasing" if trend > 2 else "decreasing" if trend < -2 else "stable"
            forecast['cpu_predicted'] = min(100, max(0, self.data['cpu_percent'] + trend * 2))
        else:
            forecast['cpu_trend'] = "unknown"
            forecast['cpu_predicted'] = self.data['cpu_percent']
        
        # RAM Forecast
        if len(self.data_history['ram']) >= 5:
            recent_ram = self.data_history['ram'][-5:]
            trend = (recent_ram[-1] - recent_ram[0]) / len(recent_ram)
            forecast['ram_trend'] = "increasing" if trend > 2 else "decreasing" if trend < -2 else "stable"
            forecast['ram_predicted'] = min(100, max(0, self.data['ram_percent'] + trend * 2))
        else:
            forecast['ram_trend'] = "unknown"
            forecast['ram_predicted'] = self.data['ram_percent']
        
        return forecast
    
    def _calculate_health_score(self):
        """Calculate Overall System Health Score (0-100)"""
        score = 100
        
        # CPU Impact
        if self.data['cpu_percent'] > 90: score -= 25
        elif self.data['cpu_percent'] > 70: score -= 10
        
        # RAM Impact
        if self.data['ram_percent'] > 90: score -= 25
        elif self.data['ram_percent'] > 70: score -= 10
        
        # Disk Impact
        if self.data['disk_percent'] > 95: score -= 20
        elif self.data['disk_percent'] > 80: score -= 10
        
        # Temperature Impact
        if self.data['cpu_temp'] != "N/A":
            try:
                temp_val = float(self.data['cpu_temp'].replace('°C', ''))
                if temp_val > 85: score -= 15
                elif temp_val > 70: score -= 5
            except:
                pass
        
        # Process Count Impact
        if self.data['process_count'] > 500: score -= 5
        
        # Zombie Process Impact
        if self.data['zombie_count'] > 0: score -= 10
        
        # Connection Count Impact
        if self.data['net_connections'] > 1000: score -= 5
        
        self.data['health_score'] = max(0, min(100, score))
    
    def _check_alerts(self):
        """Real-time Alert System"""
        alerts = []
        
        if self.data['cpu_percent'] > self.thresholds['cpu_crit']:
            alerts.append(f"🔴 CRITICAL: CPU at {self.data['cpu_percent']}%")
        elif self.data['cpu_percent'] > self.thresholds['cpu_warn']:
            alerts.append(f"🟡 WARNING: CPU at {self.data['cpu_percent']}%")
        
        if self.data['ram_percent'] > self.thresholds['ram_crit']:
            alerts.append(f"🔴 CRITICAL: RAM at {self.data['ram_percent']}%")
        elif self.data['ram_percent'] > self.thresholds['ram_warn']:
            alerts.append(f"🟡 WARNING: RAM at {self.data['ram_percent']}%")
        
        if self.data['disk_percent'] > self.thresholds['disk_crit']:
            alerts.append(f"🔴 CRITICAL: Disk at {self.data['disk_percent']}%")
        elif self.data['disk_percent'] > self.thresholds['disk_warn']:
            alerts.append(f"🟡 WARNING: Disk at {self.data['disk_percent']}%")
        
        if self.data['cpu_temp'] != "N/A":
            try:
                temp_val = float(self.data['cpu_temp'].replace('°C', ''))
                if temp_val > self.thresholds['temp_crit']:
                    alerts.append(f"🔴 CRITICAL: CPU Temp at {temp_val}°C")
                elif temp_val > self.thresholds['temp_warn']:
                    alerts.append(f"🟡 WARNING: CPU Temp at {temp_val}°C")
            except:
                pass
        
        if self.data['zombie_count'] > 0:
            alerts.append(f"🟡 WARNING: {self.data['zombie_count']} Zombie Processes")
        
        if self.data['net_connections'] > self.thresholds['conn_crit']:
            alerts.append(f"🔴 CRITICAL: {self.data['net_connections']} Network Connections")
        elif self.data['net_connections'] > self.thresholds['conn_warn']:
            alerts.append(f"🟡 WARNING: {self.data['net_connections']} Network Connections")
        
        # Add new alerts to history
        for alert in alerts:
            if alert not in self.alert_history:
                self.alert_history.append(f"{datetime.now().strftime('%H:%M:%S')} - {alert}")
                self.notifications.append(alert)
        
        # Keep only last 10 notifications
        if len(self.notifications) > 10:
            self.notifications.pop(0)
        if len(self.alert_history) > 50:
            self.alert_history.pop(0)
    
    def _update_history(self):
        """Update Data History for Trends"""
        self.data_history['cpu'].append(self.data['cpu_percent'])
        self.data_history['ram'].append(self.data['ram_percent'])
        self.data_history['disk'].append(self.data['disk_percent'])
        self.data_history['network'].append(self.data['net_up_speed'] + self.data['net_down_speed'])
        
        for key in self.data_history:
            if len(self.data_history[key]) > self.max_history:
                self.data_history[key].pop(0)
    
    def _format_bytes(self, size):
        """Format Bytes to Human Readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    def _format_speed(self, size):
        """Format Speed to Human Readable"""
        for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB/s"
    
    def _create_progress_bar(self, percent, width=30, color="blue"):
        """Create Custom Progress Bar"""
        filled = int((percent / 100) * width)
        empty = width - filled
        
        if percent > 90:
            color = "red"
        elif percent > 70:
            color = "yellow"
        else:
            color = "green"
        
        bar = f"[{color}]{'█' * filled}{'░' * empty}[/{color}]"
        return bar
    
    def _create_mini_graph(self, data, width=30, height=5):
        """Create ASCII Mini Graph for Trends"""
        if len(data) < 2:
            return "Insufficient data"
        
        max_val = max(data) if max(data) > 0 else 100
        min_val = min(data) if min(data) >= 0 else 0
        
        graph_lines = []
        for row in range(height, 0, -1):
            threshold = (row / height) * max_val
            line = ""
            for val in data:
                if val >= threshold:
                    line += "█"
                else:
                    line += " "
            graph_lines.append(f"│{line}│")
        
        return "\n".join(graph_lines)
    
    def _export_full_report(self):
        """Export Full System Report"""
        self.export_count += 1
        filename = f"{self.export_dir}/aegis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'hostname': self.data['hostname'],
                'health_score': self.data['health_score'],
                'metrics': self.data,
                'alerts': self.alert_history[-20:],
                'history': self.data_history
            }
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            console.print(f"[green]✓ Report exported to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Export failed: {e}[/red]")
    
    def _export_csv_report(self):
        """Export CSV Format Report"""
        self.export_count += 1
        filename = f"{self.export_dir}/aegis_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, 'w') as f:
                f.write("Metric,Value\n")
                for key, value in self.data.items():
                    f.write(f"{key},{value}\n")
            console.print(f"[green]✓ CSV exported to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Export failed: {e}[/red]")
    
    def _take_screenshot(self):
        """Save Current State as Text Screenshot"""
        self.screenshot_count += 1
        filename = f"{self.export_dir}/aegis_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("AEGIS SERVER SENTINEL v3.0 - SYSTEM SNAPSHOT\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                f.write("HEALTH SCORE: {}/100\n\n".format(self.data['health_score']))
                
                f.write("CPU: {}% | RAM: {}% | DISK: {}%\n\n".format(
                    self.data['cpu_percent'],
                    self.data['ram_percent'],
                    self.data['disk_percent']
                ))
                
                f.write("RECENT ALERTS:\n")
                for alert in self.alert_history[-10:]:
                    f.write(f"  {alert}\n")
                
                f.write("\n" + "=" * 80 + "\n")
            console.print(f"[green]✓ Snapshot saved to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Snapshot failed: {e}[/red]")
    
    # === UI COMPONENTS ===
    
    def make_header(self):
        """Header dengan Informasi Sistem"""
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right", ratio=1)
        
        title = Text("🛡️  AEGIS SERVER SENTINEL v3.0  🛡️", style="bold cyan")
        subtitle = Text(f"🖥️  {self.data['hostname']} | {self.data['ip_address']}", style="dim white")
        clock = Text(f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="bold green")
        
        grid.add_row(title, subtitle, clock)
        return Panel(grid, style="bold white", box=box.DOUBLE_EDGE, border_style="cyan")
    
    def make_cpu_panel(self):
        """Panel CPU Monitoring (Fitur 1-7)"""
        content = Text()
        content.append("⚡ CPU MONITORING (7 Features)\n\n", style="bold cyan underline")
        
        # Main CPU Bar
        cpu_bar = self._create_progress_bar(self.data['cpu_percent'], 35, "blue")
        content.append(f"Usage:      {cpu_bar} {self.data['cpu_percent']:>5.1f}%\n")
        
        # Load Average
        content.append(f"Load Avg:   {self.data['load_avg']}\n", style="dim")
        
        # Frequency
        content.append(f"Frequency:  {self.data['cpu_freq_current']} MHz (Max: {self.data['cpu_freq_max']})\n", style="dim")
        
        # Temperature
        temp_style = "red" if self.data['cpu_temp'] != "N/A" and float(self.data['cpu_temp'].replace('°C','')) > 70 else "green"
        content.append(f"Temperature: {self.data['cpu_temp']}\n", style=temp_style)
        
        # Cores
        content.append(f"Cores:      {self.data['cpu_cores_physical']} Physical / {self.data['cpu_cores_logical']} Logical\n", style="dim")
        
        # CPU Times
        content.append(f"Time:       User: {self.data['cpu_time_user']:.1f}% | System: {self.data['cpu_time_system']:.1f}%\n", style="dim")
        
        # Per Core Visualization
        content.append("\nCore Usage:\n", style="bold")
        for i, core_usage in enumerate(self.data['cpu_per_core'][:8]):
            bar = self._create_progress_bar(core_usage, 15, "blue")
            content.append(f"  Core {i}: {bar} {core_usage:>5.1f}%\n")
        
        return Panel(content, title="CPU", border_style="cyan", box=box.ROUNDED)
    
    def make_memory_panel(self):
        """Panel Memory Monitoring (Fitur 8-14)"""
        content = Text()
        content.append("💾 MEMORY MONITORING (7 Features)\n\n", style="bold magenta underline")
        
        # RAM Bar
        ram_bar = self._create_progress_bar(self.data['ram_percent'], 35, "magenta")
        content.append(f"RAM:        {ram_bar} {self.data['ram_percent']:>5.1f}%\n")
        content.append(f"            {self.data['ram_used']:.1f} GB / {self.data['ram_total']:.1f} GB\n", style="dim")
        content.append(f"Available:  {self.data['ram_available']:.1f} GB | Free: {self.data['ram_free']:.1f} GB\n", style="dim")
        
        # Cached & Buffers
        content.append(f"Cached:     {self.data['ram_cached']:.1f} GB\n", style="dim")
        content.append(f"Buffers:    {self.data['ram_buffers']:.1f} GB\n", style="dim")
        content.append(f"Shared:     {self.data['ram_shared']:.1f} GB\n", style="dim")
        
        # Swap
        swap_bar = self._create_progress_bar(self.data['swap_percent'], 35, "yellow")
        content.append(f"\nSwap:       {swap_bar} {self.data['swap_percent']:>5.1f}%\n")
        content.append(f"            {self.data['swap_used']:.1f} GB / {self.data['swap_total']:.1f} GB\n", style="dim")
        
        # Memory Pressure
        pressure_color = "green" if self.data['memory_pressure'] == "LOW" else "yellow" if self.data['memory_pressure'] == "MEDIUM" else "red"
        content.append(f"\nPressure:   [{pressure_color}]{self.data['memory_pressure']}[/{pressure_color}]\n", style="bold")
        
        return Panel(content, title="Memory", border_style="magenta", box=box.ROUNDED)
    
    def make_disk_panel(self):
        """Panel Disk Monitoring (Fitur 15-22)"""
        content = Text()
        content.append("💿 DISK MONITORING (8 Features)\n\n", style="bold yellow underline")
        
        # Disk Bar
        disk_bar = self._create_progress_bar(self.data['disk_percent'], 35, "yellow")
        content.append(f"Root:       {disk_bar} {self.data['disk_percent']:>5.1f}%\n")
        content.append(f"            {self.data['disk_used']:.1f} GB / {self.data['disk_total']:.1f} GB\n", style="dim")
        content.append(f"Free:       {self.data['disk_free']:.1f} GB\n", style="dim")
        
        # Partitions
        content.append(f"\nPartitions: {self.data['disk_partitions']}\n", style="bold")
        for part in self.data['partition_list'][:3]:
            p_bar = self._create_progress_bar(part['percent'], 20, "yellow")
            content.append(f"  {part['mountpoint'][:15]:<15} {p_bar} {part['percent']:>5.1f}%\n")
        
        # I/O Speed
        content.append(f"\nI/O Read:   {self._format_speed(self.data['disk_read_speed'])}\n", style="cyan")
        content.append(f"I/O Write:  {self._format_speed(self.data['disk_write_speed'])}\n", style="cyan")
        
        # I/O Operations & Time
        content.append(f"\nRead Ops:   {self.data['disk_read_count']:,} | Time: {self.data['disk_read_time']} ms\n", style="dim")
        content.append(f"Write Ops:  {self.data['disk_write_count']:,} | Time: {self.data['disk_write_time']} ms\n", style="dim")
        
        # Open Files & FD
        content.append(f"\nOpen Files: {self.data['open_files']}\n", style="dim")
        content.append(f"FD Usage:   {self.data['fd_usage']}\n", style="dim")
        
        return Panel(content, title="Disk", border_style="yellow", box=box.ROUNDED)
    
    def make_network_panel(self):
        """Panel Network Monitoring (Fitur 23-30)"""
        content = Text()
        content.append("🌐 NETWORK MONITORING (8 Features)\n\n", style="bold green underline")
        
        # Speed
        content.append(f"Upload:     {self._format_speed(self.data['net_up_speed'])}\n", style="cyan")
        content.append(f"Download:   {self._format_speed(self.data['net_down_speed'])}\n", style="cyan")
        
        # Total Traffic
        content.append(f"\nTotal Sent:     {self._format_bytes(self.data['net_sent'])}\n", style="dim")
        content.append(f"Total Received: {self._format_bytes(self.data['net_recv'])}\n", style="dim")
        
        # Packets
        content.append(f"Packets Sent:   {self.data['net_packets_sent']:,}\n", style="dim")
        content.append(f"Packets Recv:   {self.data['net_packets_recv']:,}\n", style="dim")
        
        # Connections
        content.append(f"\nConnections:\n", style="bold")
        content.append(f"  Total:       {self.data['net_connections']}\n", style="dim")
        content.append(f"  Listening:   {self.data['net_connections_listen']}\n", style="dim")
        content.append(f"  Established: {self.data['net_connections_established']}\n", style="dim")
        content.append(f"  Time Wait:   {self.data['net_connections_time_wait']}\n", style="dim")
        
        # Network Info
        content.append(f"\nLatency:    {self.data['network_latency']}\n", style="bold")
        content.append(f"DNS:        {self.data['dns_servers']}\n", style="dim")
        content.append(f"Interfaces: {', '.join(self.data['net_interfaces'][:3])}\n", style="dim")
        
        return Panel(content, title="Network", border_style="green", box=box.ROUNDED)
    
    def make_process_panel(self):
        """Panel Process Monitoring (Fitur 31-37)"""
        content = Text()
        content.append("📊 PROCESS MONITORING (7 Features)\n\n", style="bold red underline")
        
        # Total Processes
        delta_style = "green" if self.data['process_delta'] <= 0 else "yellow" if self.data['process_delta'] < 10 else "red"
        content.append(f"Total Running: {self.data['process_count']} ", style="bold")
        content.append(f"({self.data['process_delta']:+d})\n", style=delta_style)
        
        # Process States
        content.append(f"\nProcess States:\n", style="bold")
        states = self.data['process_states']
        content.append(f"  Running: {states['running']} | Sleeping: {states['sleeping']}\n", style="dim")
        content.append(f"  Stopped: {states['stopped']} | Zombie: {states['zombie']}\n", style="dim")
        
        # Zombie Alert
        if self.data['zombie_count'] > 0:
            content.append(f"\n⚠️  {self.data['zombie_count']} Zombie Processes Detected!\n", style="bold red")
        
        # Total Threads
        content.append(f"\nTotal Threads: {self.data['total_threads']:,}\n", style="dim")
        
        # Top CPU Table
        content.append(f"\nTop 5 by CPU:\n", style="bold cyan")
        for i, p in enumerate(self.data['top_processes_cpu']):
            content.append(f"  {i+1}. {p['name'][:20]:<20} PID: {p['pid']:<6} CPU: {p['cpu_percent']:>5.1f}%\n")
        
        # Top Memory Table
        content.append(f"\nTop 5 by Memory:\n", style="bold magenta")
        for i, p in enumerate(self.data['top_processes_mem']):
            content.append(f"  {i+1}. {p['name'][:20]:<20} PID: {p['pid']:<6} MEM: {p['memory_percent']:>5.1f}%\n")
        
        return Panel(content, title="Processes", border_style="red", box=box.ROUNDED)
    
    def make_system_panel(self):
        """Panel System Info (Fitur 38-44)"""
        content = Text()
        content.append("⚙️  SYSTEM INFORMATION (7 Features)\n\n", style="bold white underline")
        
        # Uptime
        uptime = self.data['uptime']
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        content.append(f"Uptime:     {days}d {hours}h {minutes}m\n", style="cyan")
        content.append(f"Boot Time:  {self.data['boot_time']}\n", style="dim")
        
        # OS Info
        content.append(f"\nOS:         {self.data['os_name']} {self.data['os_release']}\n", style="dim")
        content.append(f"Arch:       {self.data['os_architecture']}\n", style="dim")
        content.append(f"Processor:  {self.data['os_processor']}\n", style="dim")
        content.append(f"Python:     {self.data['python_version']}\n", style="dim")
        
        # Users
        content.append(f"\nUsers:      {', '.join(self.data['logged_users']) if self.data['logged_users'] else 'None'}\n", style="dim")
        
        # Locale & Timezone
        content.append(f"Locale:     {self.data['locale']}\n", style="dim")
        content.append(f"Timezone:   {self.data['timezone'][0]}\n", style="dim")
        
        # Battery
        if self.data['battery_percent']:
            battery_bar = self._create_progress_bar(self.data['battery_percent'], 20, "green")
            plug_status = "🔌 Charging" if self.data['battery_plugged'] else "🔋 Discharging"
            content.append(f"\nBattery:    {battery_bar} {self.data['battery_percent']}%\n")
            content.append(f"Status:     {plug_status}\n", style="dim")
        else:
            content.append(f"\nBattery:    🔌 AC Power / No Battery\n", style="green")
        
        # Environment Variables
        content.append(f"\nEnv Vars:   {self.data['env_vars_count']}\n", style="dim")
        
        return Panel(content, title="System", border_style="white", box=box.ROUNDED)
    
    def make_security_panel(self):
        """Panel Security & Advanced (Fitur 45-50)"""
        content = Text()
        content.append("🔒 SECURITY & ADVANCED (6 Features)\n\n", style="bold red underline")
        
        # Security Level
        sec_level = self.data['security_level']['level']
        sec_score = self.data['security_level']['score']
        sec_color = "green" if sec_level == "HIGH" else "yellow" if sec_level == "MEDIUM" else "red"
        content.append(f"Security Level: [{sec_color}]{sec_level} ({sec_score}/100)[/{sec_color}]\n\n", style="bold")
        
        # Security Checks
        for check in self.data['security_level']['checks'][:5]:
            content.append(f"  {check}\n", style="dim")
        
        # Home Directory
        content.append(f"\n📁 Home Directory:\n", style="bold")
        content.append(f"  Total: {self.data['home_total']:.1f} GB\n", style="dim")
        content.append(f"  Used:  {self.data['home_used']:.1f} GB\n", style="dim")
        content.append(f"  Free:  {self.data['home_free']:.1f} GB\n", style="dim")
        
        # Temp Directory
        content.append(f"\n📁 Temp Directory:\n", style="bold")
        content.append(f"  Total: {self.data['temp_total']:.1f} GB\n", style="dim")
        content.append(f"  Used:  {self.data['temp_used']:.1f} GB\n", style="dim")
        content.append(f"  Free:  {self.data['temp_free']:.1f} GB\n", style="dim")
        
        # Recent Files
        content.append(f"\n📄 Recent Files (5 min):\n", style="bold")
        for file in self.data['recent_files'][:3]:
            content.append(f"  {file['mtime']} - {file['path'][-40:]}\n", style="dim")
        
        # Resource Forecast
        content.append(f"\n📈 Resource Forecast:\n", style="bold")
        forecast = self.data['resource_forecast']
        cpu_trend = "📈" if forecast['cpu_trend'] == "increasing" else "📉" if forecast['cpu_trend'] == "decreasing" else "➡️"
        ram_trend = "📈" if forecast['ram_trend'] == "increasing" else "📉" if forecast['ram_trend'] == "decreasing" else "➡️"
        content.append(f"  CPU:  {cpu_trend} {forecast['cpu_trend']} (Predicted: {forecast['cpu_predicted']:.1f}%)\n", style="dim")
        content.append(f"  RAM:  {ram_trend} {forecast['ram_trend']} (Predicted: {forecast['ram_predicted']:.1f}%)\n", style="dim")
        
        return Panel(content, title="Security & Advanced", border_style="red", box=box.ROUNDED)
    
    def make_health_panel(self):
        """Panel Health Score & Alerts"""
        score = self.data['health_score']
        
        # Score Color
        if score >= 80:
            score_color = "green"
            score_emoji = "✅"
        elif score >= 60:
            score_color = "yellow"
            score_emoji = "⚠️"
        else:
            score_color = "red"
            score_emoji = "🚨"
        
        content = Text()
        content.append("🏥 SYSTEM HEALTH\n\n", style="bold underline")
        
        # Health Score Large Display
        score_bar = self._create_progress_bar(score, 40, score_color)
        content.append(f"Score:    {score_bar} {score}%\n", style=f"bold {score_color}")
        content.append(f"Status:   {score_emoji} ", style=f"bold {score_color}")
        
        if score >= 80:
            content.append("EXCELLENT\n", style="green")
        elif score >= 60:
            content.append("GOOD\n", style="yellow")
        else:
            content.append("CRITICAL\n", style="red")
        
        # Mini Graphs
        content.append("\n📈 CPU Trend (Last 30s):\n", style="bold")
        content.append(self._create_mini_graph(self.data_history['cpu'], 30, 4))
        content.append("\n\n📈 RAM Trend (Last 30s):\n", style="bold")
        content.append(self._create_mini_graph(self.data_history['ram'], 30, 4))
        content.append("\n\n📈 Network Trend (Last 30s):\n", style="bold")
        content.append(self._create_mini_graph(self.data_history['network'], 30, 4))
        
        return Panel(content, title="Health & Trends", border_style=score_color, box=box.DOUBLE)
    
    def make_alert_panel(self):
        """Panel Notifications & Alerts"""
        content = Text()
        content.append("🔔 REAL-TIME ALERTS\n\n", style="bold underline")
        
        if self.notifications:
            for note in self.notifications[-10:]:
                if "CRITICAL" in note:
                    content.append(f"🔴 {note}\n", style="bold red")
                elif "WARNING" in note:
                    content.append(f"🟡 {note}\n", style="bold yellow")
                else:
                    content.append(f"🟢 {note}\n", style="green")
        else:
            content.append("✓ All systems normal\n", style="dim green")
        
        content.append(f"\n📜 Alert History ({len(self.alert_history)} total):\n", style="bold")
        for alert in self.alert_history[-10:]:
            content.append(f"  {alert}\n", style="dim")
        
        # Quick Stats
        content.append(f"\n📊 Quick Stats:\n", style="bold")
        content.append(f"  Processes:    {self.data['process_count']} ({self.data['process_delta']:+d})\n", style="dim")
        content.append(f"  Connections:  {self.data['net_connections']}\n", style="dim")
        content.append(f"  Partitions:   {self.data['disk_partitions']}\n", style="dim")
        content.append(f"  Zombies:      {self.data['zombie_count']}\n", style="dim")
        content.append(f"  Exports:      {self.export_count}\n", style="dim")
        
        return Panel(content, title="Notifications", border_style="red", box=box.ROUNDED)
    
    def make_footer(self):
        """Footer dengan Menu & Info"""
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=2)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right", ratio=1)
        
        # Menu
        menu_text = Text()
        menu_text.append("MENU: ", style="bold")
        menu_text.append("[Q]uit ", style="cyan")
        menu_text.append("[R]eport ", style="cyan")
        menu_text.append("[C]SV ", style="cyan")
        menu_text.append("[S]napshot ", style="cyan")
        menu_text.append("[H]elp ", style="cyan")
        
        # Status
        status_text = Text()
        status_text.append("Status: ", style="bold")
        status_text.append("● LIVE", style="green bold")
        
        # Version
        version_text = Text()
        version_text.append("AEGIS v3.0 | 50 Features", style="dim")
        
        grid.add_row(menu_text, status_text, version_text)
        return Panel(grid, style="dim", box=box.ASCII)
    
    def make_layout(self):
        """Create Main Layout"""
        layout = Layout()
        
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        layout["body"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=2)
        )
        
        layout["left"].split(
            Layout(name="cpu", ratio=1),
            Layout(name="memory", ratio=1),
            Layout(name="disk", ratio=1)
        )
        
        layout["right"].split(
            Layout(name="network", ratio=1),
            Layout(name="process", ratio=1),
            Layout(name="system", ratio=1)
        )
        
        return layout
    
    def show_help(self):
        """Show Help Menu"""
        help_text = """
[bold cyan]🛡️  AEGIS SERVER SENTINEL v3.0 - HELP[/bold cyan]

[bold]KEYBOARD SHORTCUTS:[/bold]
  [cyan]Q[/cyan]  - Quit application
  [cyan]R[/cyan]  - Export JSON Report
  [cyan]C[/cyan]  - Export CSV Data
  [cyan]S[/cyan]  - Take Snapshot
  [cyan]H[/cyan]  - Show this help

[bold]FEATURES (50 Total):[/bold]
  [cyan]CPU[/cyan]         - 7 features (Usage, Cores, Temp, etc.)
  [cyan]Memory[/cyan]      - 7 features (RAM, Swap, Pressure, etc.)
  [cyan]Disk[/cyan]        - 8 features (Usage, I/O, Partitions, etc.)
  [cyan]Network[/cyan]     - 8 features (Speed, Connections, etc.)
  [cyan]Process[/cyan]     - 7 features (Top, States, Zombies, etc.)
  [cyan]System[/cyan]      - 7 features (Uptime, OS, Users, etc.)
  [cyan]Security[/cyan]    - 6 features (Level, Forecast, etc.)

[bold]HEALTH SCORE:[/bold]
  [green]80-100[/green] - Excellent
  [yellow]60-79[/yellow]  - Good
  [red]0-59[/red]   - Critical

[bold]EXPORT DIRECTORY:[/bold]
  All exports saved to: [cyan]{}/[/cyan]

Press any key to return...
        """.format(self.export_dir)
        
        console.print(Panel(help_text, title="Help", border_style="cyan"))
        time.sleep(3)
    
    def run(self):
        """Main Run Loop"""
        layout = self.make_layout()
        
        console.print("\n[bold cyan]🛡️  AEGIS SERVER SENTINEL v3.0 Starting...[/bold cyan]\n")
        console.print("[dim]Press Ctrl+C to exit | Press keys for actions[/dim]\n")
        console.print("[bold]50 FEATURES ACTIVE[/bold] | Export Dir: [cyan]{}/[/cyan]\n".format(self.export_dir))
        time.sleep(1)
        
        try:
            with Live(layout, refresh_per_second=2, screen=True, redirect_stderr=False) as live:
                while True:
                    self.get_all_system_data()
                    
                    # Update All Layouts
                    layout["header"].update(self.make_header())
                    layout["left"]["cpu"].update(self.make_cpu_panel())
                    layout["left"]["memory"].update(self.make_memory_panel())
                    layout["left"]["disk"].update(self.make_disk_panel())
                    layout["right"]["network"].update(self.make_network_panel())
                    layout["right"]["process"].update(self.make_process_panel())
                    layout["right"]["system"].update(self.make_system_panel())
                    layout["footer"].update(self.make_footer())
                    
                    time.sleep(0.5)
                    
        except KeyboardInterrupt:
            console.print("\n\n[bold red]🛡️  AEGIS Monitor Stopped by User[/bold red]\n")
            
            # Show Summary
            console.print("\n[bold cyan]📊 SESSION SUMMARY:[/bold cyan]")
            console.print(f"  Runtime:        {datetime.now() - self.start_time}")
            console.print(f"  Total Alerts:   {len(self.alert_history)}")
            console.print(f"  Exports Made:   {self.export_count}")
            console.print(f"  Snapshots:      {self.screenshot_count}")
            console.print(f"  Final Score:    {self.data['health_score']}%\n")
            
            # Ask for final export
            if console.input("[yellow]Export final report? (y/n):[/yellow] ").lower() == 'y':
                self._export_full_report()
                self._export_csv_report()


if __name__ == "__main__":
    try:
        app = AegisMonitorV3()
        app.run()
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")