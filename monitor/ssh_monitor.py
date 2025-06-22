# ssh_monitor_improved.py

import os
import re
import sys
import json
import paramiko
from datetime import datetime
from contextlib import contextmanager
from vcenter.vcenter_task import VCenterClient, VMwareTask


class SSHMonitor:
    def __init__(self, hostname, username, password=None, private_key_path=None, port=22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.private_key_path = private_key_path
        self.port = port
        self.client = None

    @contextmanager
    def ssh_connection(self):
        """Context manager for SSH connections"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect with password or private key
            if self.private_key_path and os.path.exists(self.private_key_path):
                private_key = paramiko.RSAKey.from_private_key_file(self.private_key_path)
                self.client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    pkey=private_key,
                    timeout=30
                )
            elif self.password:
                self.client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=30
                )
            else:
                raise ValueError("Either password or private_key_path must be provided")
                
            yield self.client
            
        except Exception as e:
            print(f"❌ SSH connection failed: {e}")
            raise
        finally:
            if self.client:
                self.client.close()

    def execute_command(self, command, timeout=30, use_sudo=False):
        """Execute a command via SSH with improved sudo handling"""
        try:
            # Detect if sudo is needed
            needs_sudo = command.strip().startswith('sudo') or use_sudo
            
            if needs_sudo and self.password:
                # Use -S flag to read password from stdin
                if not command.strip().startswith('sudo'):
                    command = f"sudo -S {command}"
                elif 'sudo -S' not in command:
                    command = command.replace('sudo', 'sudo -S', 1)
                
                # Execute command
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
                
                # Send password to stdin for sudo
                stdin.write(self.password + '\n')
                stdin.flush()
                stdin.close()
                
            elif needs_sudo and not self.password:
                # Try passwordless sudo first
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
                
            else:
                # Regular command without sudo
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            
            # Get output and error
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            exit_code = stdout.channel.recv_exit_status()
            
            # Check for sudo-specific errors
            if exit_code != 0 and 'sudo:' in error:
                return {
                    'success': False,
                    'output': output,
                    'error': f"Sudo error: {error}",
                    'exit_code': exit_code,
                    'sudo_issue': True
                }
            
            return {
                'success': exit_code == 0,
                'output': output,
                'error': error,
                'exit_code': exit_code,
                'sudo_issue': False
            }
            
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e),
                'exit_code': -1,
                'sudo_issue': False
            }

    def execute_command_with_fallback(self, command, timeout=30):
        """Execute command with fallback options for sudo issues"""
        # Try original command first
        result = self.execute_command(command, timeout)
        
        if result['success']:
            return result
        
        # If sudo failed, try alternatives
        if 'sudo:' in result.get('error', '') or result.get('sudo_issue', False):
            print(f"⚠️  Sudo failed for command: {command}")
            
            # Try without sudo if possible
            if command.strip().startswith('sudo '):
                fallback_command = command.replace('sudo ', '', 1)
                print(f"🔄 Trying without sudo: {fallback_command}")
                fallback_result = self.execute_command(fallback_command, timeout)
                
                if fallback_result['success']:
                    fallback_result['warning'] = "Command executed without sudo privileges"
                    return fallback_result
            
            # Mark as sudo permission issue
            result['error'] = f"Sudo permission denied or misconfigured: {result['error']}"
            result['sudo_permission_issue'] = True
        
        return result

    def get_system_info(self):
        """Get basic system information"""
        commands = {
            'hostname': 'hostname -f',
            'uptime': 'uptime',
            'kernel': 'uname -r',
            'os_info': 'cat /etc/os-release | head -5',
            'cpu_info': 'lscpu | grep -E "Model name|CPU\\(s\\)|Architecture"',
            'memory_info': 'free -h',
            'load_average': 'cat /proc/loadavg'
        }
        
        results = {}
        for key, cmd in commands.items():
            result = self.execute_command_with_fallback(cmd)
            results[key] = {
                'output': result['output'] if result['success'] else f"Error: {result['error']}",
                'success': result['success'],
                'warning': result.get('warning', '')
            }
        
        return results

    def get_process_info(self):
        """Get top processes by CPU and memory usage"""
        commands = {
            'top_cpu': 'ps aux --sort=-%cpu | head -15',
            'top_memory': 'ps aux --sort=-%mem | head -15',
            'process_count': 'ps aux | wc -l',
            'running_processes': 'ps aux | grep -v "\\[" | wc -l'
        }
        
        results = {}
        for key, cmd in commands.items():
            result = self.execute_command_with_fallback(cmd)
            results[key] = {
                'output': result['output'] if result['success'] else f"Error: {result['error']}",
                'success': result['success'],
                'warning': result.get('warning', '')
            }
        
        return results

    def get_disk_info(self):
        """Get disk usage and storage information"""
        commands = {
            'disk_usage': 'df -h',
            'disk_blocks': 'lsblk',
            'disk_usage_root': 'du -h --max-depth=1 / 2>/dev/null | sort -hr | head -n 20',
            'inode_usage': 'df -i',
            'mount_points': 'mount | grep -E "^/dev" | sort'
        }
        
        results = {}
        for key, cmd in commands.items():
            result = self.execute_command_with_fallback(cmd)
            results[key] = {
                'output': result['output'] if result['success'] else f"Error: {result['error']}",
                'success': result['success'],
                'warning': result.get('warning', '')
            }
        
        return results

    def get_network_info(self):
        """Get network information"""
        commands = {
            'network_interfaces': 'ip addr show',
            'network_stats': 'ss -tuln',
            'network_connections': 'ss -tun | head -20'
        }
        
        results = {}
        for key, cmd in commands.items():
            result = self.execute_command_with_fallback(cmd)
            results[key] = {
                'output': result['output'] if result['success'] else f"Error: {result['error']}",
                'success': result['success'],
                'warning': result.get('warning', '')
            }
        
        return results

    def get_service_status(self):
        """Get system service status"""
        commands = {
            'failed_services': 'systemctl --failed --no-pager',
            'running_services': 'systemctl list-units --type=service --state=running --no-pager | head -15',
            'system_status': 'systemctl status --no-pager -l | head -20'
        }
        
        results = {}
        for key, cmd in commands.items():
            result = self.execute_command_with_fallback(cmd)
            results[key] = {
                'output': result['output'] if result['success'] else f"Error: {result['error']}",
                'success': result['success'],
                'warning': result.get('warning', '')
            }

        return results

    def get_security_logs(self, lines=50):
        """Get authentication and security logs with improved sudo handling"""
        commands = {
            'auth_log': f'sudo -S tail -n {lines} /var/log/auth.log 2>/dev/null || tail -n {lines} /var/log/secure 2>/dev/null || echo "Auth log not accessible"',
            'failed_logins': 'sudo -S grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10 || echo "Failed login log not accessible"',
            'successful_logins': 'sudo -S grep "Accepted password" /var/log/auth.log 2>/dev/null | tail -10 || echo "Successful login log not accessible"',
            'sudo_commands': 'sudo -S grep "sudo:" /var/log/auth.log 2>/dev/null | tail -15 || echo "Sudo log not accessible"',
            'current_users': 'who',
            'last_logins': 'last | head -10'
        }
        
        results = {}
        for key, cmd in commands.items():
            result = self.execute_command_with_fallback(cmd, timeout=45)
            results[key] = {
                'output': result['output'] if result['success'] else f"Error: {result['error']}",
                'success': result['success'],
                'warning': result.get('warning', ''),
                'sudo_issue': result.get('sudo_permission_issue', False)
            }
        
        return results

    def get_additional_security_checks(self):
        """Run extra security checks with better sudo handling"""
        commands = {
            'root_suspicious_processes': (
                'ps -eo user,pid,cmd --sort=user | grep "^root" | '
                'grep -Ev "sshd|init|systemd|kthreadd|kworker|cron|rsyslog|dbus|rpc|agetty|bash" | head -10'
            ),
            'recent_tmp_exec_files': (
                'find /tmp /var/tmp /dev/shm -type f -executable -mtime -2 2>/dev/null | head -10'
            ),
            'recent_new_users': (
                'sudo -S tail -20 /etc/passwd'
            ),
            'user_crontab_entries': (
                'for u in $(cut -f1 -d: /etc/passwd); do sudo -S crontab -u $u -l 2>/dev/null; done | head -20'
            ),
            'ssh_authorized_keys': (
                'for u in $(cut -f1 -d: /etc/passwd); do '
                '[ -f /home/$u/.ssh/authorized_keys ] && echo "[$u]:" && '
                'cat /home/$u/.ssh/authorized_keys; done | head -40'
            ),
            'high_ports_open': (
                'ss -tulnp | grep -v ":22 " | grep -E ":[0-9]{4,}" | head -15'
            ),
            'suid_files': (
                'find / -perm /6000 -type f 2>/dev/null | grep -vE "/usr/(bin|sbin)|/bin|/sbin" | head -10'
            )
        }
        
        results = {}
        for key, cmd in commands.items():
            result = self.execute_command_with_fallback(cmd, timeout=60)
            results[key] = {
                'output': result['output'] if result['success'] else f"Error: {result['error']}",
                'success': result['success'],
                'warning': result.get('warning', ''),
                'sudo_issue': result.get('sudo_permission_issue', False)
            }

        return results

    def check_sudo_configuration(self):
        """Check sudo configuration and permissions"""
        checks = {
            'sudo_version': 'sudo --version | head -1',
            'sudo_list': 'sudo -l -n 2>&1 || echo "Cannot list sudo privileges"',
            'sudoers_syntax': 'sudo -n visudo -c 2>&1 || echo "Cannot check sudoers syntax"',
            'user_groups': 'groups',
            'sudo_group_members': 'getent group sudo 2>/dev/null || getent group wheel 2>/dev/null || echo "No sudo group found"'
        }
        
        results = {}
        for key, cmd in checks.items():
            result = self.execute_command_with_fallback(cmd)
            results[key] = {
                'output': result['output'] if result['success'] else f"Error: {result['error']}",
                'success': result['success'],
                'warning': result.get('warning', '')
            }
        
        return results

    def get_comprehensive_report(self):
        """Get comprehensive system monitoring report with sudo diagnostics"""
        try:
            with self.ssh_connection():
                print(f"🔗 Connected to {self.hostname}")
                
                # Check sudo configuration first
                sudo_check = self.check_sudo_configuration()
                
                report = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'hostname': self.hostname,
                    'connection_status': 'Connected',
                    'sudo_configuration': sudo_check,
                    'system_info': self.get_system_info(),
                    'process_info': self.get_process_info(),
                    'disk_info': self.get_disk_info(),
                    'network_info': self.get_network_info(),
                    'services_info': self.get_service_status(),
                    'security_logs': self.get_security_logs(),
                    'additional_security': self.get_additional_security_checks(),
                }
                return report
            
        except Exception as e:
            return {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'hostname': self.hostname,
                'connection_status': f'Failed: {str(e)}',
                'error': str(e)
            }


def format_ssh_report_for_ai(report):
    """Format SSH monitoring report for AI analysis with sudo diagnostics"""
    if 'error' in report:
        return f"SSH Connection Failed: {report['error']}"

    # Check for sudo issues
    sudo_issues = []
    for section_name, section_data in report.items():
        if isinstance(section_data, dict):
            for key, value in section_data.items():
                if isinstance(value, dict) and value.get('sudo_issue', False):
                    sudo_issues.append(f"{section_name}.{key}")

    formatted_report = f"""
SSH SYSTEM MONITORING REPORT
=============================
Hostname: {report.get('hostname', 'Unknown')}
Timestamp: {report.get('timestamp', 'Unknown')}
Connection: {report.get('connection_status', 'Unknown')}

SUDO CONFIGURATION CHECK:
{'-' * 30}
Sudo Version: {report.get('sudo_configuration', {}).get('sudo_version', {}).get('output', 'N/A')}
User Groups: {report.get('sudo_configuration', {}).get('user_groups', {}).get('output', 'N/A')}
Sudo Privileges: {report.get('sudo_configuration', {}).get('sudo_list', {}).get('output', 'N/A')}
Sudo Group Members: {report.get('sudo_configuration', {}).get('sudo_group_members', {}).get('output', 'N/A')}

{"⚠️  SUDO ISSUES DETECTED IN: " + ", ".join(sudo_issues) if sudo_issues else "✅ No major sudo issues detected"}

SYSTEM INFORMATION:
{'-' * 30}
Hostname: {report['system_info'].get('hostname', {}).get('output', 'N/A')}
Uptime: {report['system_info'].get('uptime', {}).get('output', 'N/A')}
Kernel: {report['system_info'].get('kernel', {}).get('output', 'N/A')}
OS Info: {report['system_info'].get('os_info', {}).get('output', 'N/A')}
CPU Info: {report['system_info'].get('cpu_info', {}).get('output', 'N/A')}
Memory: {report['system_info'].get('memory_info', {}).get('output', 'N/A')}
Load Average: {report['system_info'].get('load_average', {}).get('output', 'N/A')}

PROCESS INFORMATION:
{'-' * 30}
Total Processes: {report['process_info'].get('process_count', {}).get('output', 'N/A')}
Running Processes: {report['process_info'].get('running_processes', {}).get('output', 'N/A')}

Top CPU Consuming Processes:
{report['process_info'].get('top_cpu', {}).get('output', 'N/A')}

Top Memory Consuming Processes:
{report['process_info'].get('top_memory', {}).get('output', 'N/A')}

DISK INFORMATION:
{'-' * 30}
Disk Usage:
{report['disk_info'].get('disk_usage', {}).get('output', 'N/A')}

Block Devices:
{report['disk_info'].get('disk_blocks', {}).get('output', 'N/A')}

Directory Sizes (Root):
{report['disk_info'].get('disk_usage_root', {}).get('output', 'N/A')}

NETWORK INFORMATION:
{'-' * 30}
Current Users: {report['security_logs'].get('current_users', {}).get('output', 'N/A')}
Network Connections: {report['network_info'].get('network_connections', {}).get('output', 'N/A')}

SYSTEM SERVICES:
{'-' * 30}
Failed Services:
{report['services_info'].get('failed_services', {}).get('output', 'Service status not available')}

Running Services (Sample):
{report['services_info'].get('running_services', {}).get('output', 'Service status not available')}

System Status:
{report['services_info'].get('system_status', {}).get('output', 'System status not available')}

SECURITY & AUTHENTICATION:
{'-' * 30}
Recent Failed Logins:
{report['security_logs'].get('failed_logins', {}).get('output', 'N/A')}
{"⚠️  Sudo permission issue" if report['security_logs'].get('failed_logins', {}).get('sudo_issue') else ""}

Recent Successful Logins:
{report['security_logs'].get('successful_logins', {}).get('output', 'N/A')}

Recent Sudo Commands:
{report['security_logs'].get('sudo_commands', {}).get('output', 'N/A')}

Last Logins:
{report['security_logs'].get('last_logins', {}).get('output', 'N/A')}

ADDITIONAL SECURITY CHECKS:
{'-' * 30}
Root suspicious processes:
{report.get('additional_security', {}).get('root_suspicious_processes', {}).get('output', 'N/A')}

Recently executable files in /tmp, /var/tmp, /dev/shm:
{report.get('additional_security', {}).get('recent_tmp_exec_files', {}).get('output', 'N/A')}

New users in /etc/passwd (last 20 lines):
{report.get('additional_security', {}).get('recent_new_users', {}).get('output', 'N/A')}
{"⚠️  Sudo permission issue" if report.get('additional_security', {}).get('recent_new_users', {}).get('sudo_issue') else ""}

User crontab entries:
{report.get('additional_security', {}).get('user_crontab_entries', {}).get('output', 'N/A')}

SSH authorized_keys (sample):
{report.get('additional_security', {}).get('ssh_authorized_keys', {}).get('output', 'N/A')}

High numbered ports open (excluding 22):
{report.get('additional_security', {}).get('high_ports_open', {}).get('output', 'N/A')}

SUID/SGID suspicious files:
{report.get('additional_security', {}).get('suid_files', {}).get('output', 'N/A')}

"""
    return formatted_report


def get_vm_ssh_analysis(vm_name):
    """Get SSH monitoring data for a VM with improved error handling"""
    # Get SSH credentials from environment
    ssh_username = os.environ.get("LINUX_SSH_USER")
    ssh_password = os.environ.get("LINUX_SSH_PASS")
    ssh_private_key_path = os.environ.get("LINUX_SSH_KEY")
    ssh_port = int(os.environ.get("LINUX_SSH_PORT", 22))

    # Get IP from vCenter
    vc_host = os.environ.get("VC_HOST")
    vc_user = os.environ.get("VC_USERNAME")
    vc_pass = os.environ.get("VC_PASSWORD")
    if not (vc_host and vc_user and vc_pass):
        return "❌ vCenter credentials not configured"
    
    vc = VCenterClient(vc_host, vc_user, vc_pass)
    try:
        si = vc.get_instance()
        info = VMwareTask.get_vm_info(si, vm_name)
        if not info:
            return f"❌ VM '{vm_name}' not found in vCenter."
        vm_ip_address = info.get("ip_address")
        if not vm_ip_address:
            return f"❌ No IP found for VM '{vm_name}'. VMware Tools may not be running."
    finally:
        vc.disconnect()

    if not ssh_username:
        return "❌ No SSH username configured"
    
    if not ssh_password and not ssh_private_key_path:
        return "❌ No SSH authentication method configured (password or private key)"
    
    print(f"🔗 Connecting to {vm_ip_address} via SSH...")
    
    try:
        monitor = SSHMonitor(
            hostname=vm_ip_address,
            username=ssh_username,
            password=ssh_password,
            private_key_path=ssh_private_key_path,
            port=ssh_port
        )
        
        report = monitor.get_comprehensive_report()
        
        if 'error' in report:
            return f"❌ SSH connection failed: {report['error']}"
        
        return format_ssh_report_for_ai(report)
        
    except Exception as e:
        return f"❌ SSH monitoring failed: {str(e)}"