#!/usr/bin/env python3
"""
Advanced Linux Privilege Escalation Enumeration Tool v3.0
Enterprise-grade security auditing and privilege escalation checker
For authorized security testing and penetration testing only.

Python YetkiYukseltme.py

""" 

import os
import sys
import pwd
import grp
import subprocess
import socket
import re
import stat
from pathlib import Path
from datetime import datetime
import platform

# ============================================================================
# COLORS
# ============================================================================
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ============================================================================
# PRIVILEGE ESCALATION CHECKER
# ============================================================================
class PrivEscChecker:
    """Advanced privilege escalation enumeration tool"""
    
    def __init__(self):
        self.current_user = pwd.getpwuid(os.getuid()).pw_name
        self.current_uid = os.getuid()
        self.current_gid = os.getgid()
        self.findings = []
        self.vulnerabilities = []
        
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Colors.BOLD}{Colors.CYAN}╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║     Linux Privilege Escalation Enumeration Tool v3.0              ║
║              Advanced Security Auditing Framework                 ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝{Colors.END}
{Colors.YELLOW}[!] For authorized security testing only{Colors.END}
"""
        print(banner)
    
    def print_section(self, title):
        """Print section header"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] {title}{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")
    
    def add_finding(self, severity, category, description, details=""):
        """Add a finding to the results"""
        finding = {
            'severity': severity,  # critical, high, medium, low, info
            'category': category,
            'description': description,
            'details': details
        }
        self.findings.append(finding)
        
        # Print immediately
        severity_colors = {
            'critical': Colors.RED,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.CYAN,
            'info': Colors.BLUE
        }
        color = severity_colors.get(severity, Colors.END)
        
        print(f"{color}[{severity.upper()}]{Colors.END} {description}")
        if details:
            print(f"  └─> {details}")
    
    def run_command(self, cmd, shell=False):
        """Run a shell command and return output"""
        try:
            if isinstance(cmd, str):
                cmd = cmd.split() if not shell else cmd
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=shell,
                timeout=10
            )
            return result.stdout.strip()
        except:
            return ""
    
    def check_system_info(self):
        """Gather basic system information"""
        self.print_section("System Information")
        
        # Current user info
        print(f"{Colors.GREEN}[+] Current User:{Colors.END} {self.current_user}")
        print(f"{Colors.GREEN}[+] UID:{Colors.END} {self.current_uid}")
        print(f"{Colors.GREEN}[+] GID:{Colors.END} {self.current_gid}")
        
        # Groups
        groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
        print(f"{Colors.GREEN}[+] Groups:{Colors.END} {', '.join(groups)}")
        
        # Hostname
        hostname = socket.gethostname()
        print(f"{Colors.GREEN}[+] Hostname:{Colors.END} {hostname}")
        
        # OS info
        os_info = self.run_command("cat /etc/os-release")
        if os_info:
            for line in os_info.split('\n'):
                if line.startswith('PRETTY_NAME'):
                    os_name = line.split('=')[1].strip('"')
                    print(f"{Colors.GREEN}[+] OS:{Colors.END} {os_name}")
                    break
        
        # Kernel version
        kernel = self.run_command("uname -r")
        print(f"{Colors.GREEN}[+] Kernel:{Colors.END} {kernel}")
        
        # Architecture
        arch = platform.machine()
        print(f"{Colors.GREEN}[+] Architecture:{Colors.END} {arch}")
        
        # Check if kernel is vulnerable to known exploits
        if kernel:
            self.check_kernel_exploits(kernel)
    
    def check_kernel_exploits(self, kernel):
        """Check for known kernel vulnerabilities"""
        vulnerable_kernels = {
            '2.6.22': 'CVE-2009-2698 (udp_sendmsg)',
            '2.6.17': 'CVE-2009-2692 (sock_sendpage)',
            '3.13': 'CVE-2014-0038 (recvmmsg)',
            '3.13.0': 'CVE-2015-1328 (overlayfs)',
            '3.16': 'CVE-2016-5195 (Dirty COW)',
            '4.4': 'CVE-2017-16995 (BPF)',
            '4.8': 'CVE-2016-5195 (Dirty COW)',
            '4.10': 'CVE-2017-1000367 (Sudo)',
        }
        
        for vuln_kernel, exploit in vulnerable_kernels.items():
            if vuln_kernel in kernel:
                self.add_finding('high', 'Kernel Exploit', 
                               f'Vulnerable kernel detected: {exploit}',
                               f'Kernel {kernel} may be exploitable')
    
    def check_sudo_privs(self):
        """Check sudo privileges"""
        self.print_section("Sudo Privileges")
        
        # Check if user has sudo without password
        sudo_nopass = self.run_command("sudo -n -l 2>&1")
        
        if "may run the following" in sudo_nopass.lower():
            self.add_finding('critical', 'Sudo', 
                           'User has passwordless sudo privileges!',
                           sudo_nopass)
            
            # Check for dangerous sudo entries
            dangerous_commands = ['ALL', '/bin/bash', '/bin/sh', 'vi', 'vim', 
                                'less', 'more', 'nano', 'find', 'awk', 'perl', 
                                'python', 'ruby', 'node', 'nmap', 'tcpdump']
            
            for cmd in dangerous_commands:
                if cmd in sudo_nopass:
                    self.add_finding('critical', 'Sudo', 
                                   f'Dangerous sudo command found: {cmd}',
                                   'This can be used for privilege escalation')
        
        elif "password is required" not in sudo_nopass.lower():
            # Try with password
            print(f"{Colors.YELLOW}[*] Sudo requires password{Colors.END}")
            self.add_finding('info', 'Sudo', 'Sudo access available with password')
        else:
            print(f"{Colors.CYAN}[*] No sudo access{Colors.END}")
    
    def check_suid_files(self):
        """Check for SUID/SGID files"""
        self.print_section("SUID/SGID Files")
        
        print(f"{Colors.CYAN}[*] Searching for SUID files (this may take a while)...{Colors.END}")
        
        # Find SUID files
        suid_files = self.run_command("find / -perm -4000 -type f 2>/dev/null", shell=True)
        
        # Known exploitable SUID binaries
        dangerous_suid = {
            'nmap': 'nmap --interactive → !sh',
            'vim': 'vim -c ":!/bin/bash"',
            'find': 'find . -exec /bin/sh \\; -quit',
            'bash': 'bash -p',
            'more': 'more /etc/passwd → !/bin/bash',
            'less': 'less /etc/passwd → !/bin/bash',
            'nano': 'nano → ^R^X → reset; sh 1>&0 2>&0',
            'cp': 'cp /etc/shadow /tmp/shadow',
            'mv': 'mv /tmp/rootshell /bin/rootshell',
            'awk': 'awk "BEGIN {system(\\"/bin/bash\\")}"',
            'perl': 'perl -e "exec \\"/bin/bash\\";"',
            'python': 'python -c "import os; os.system(\\"/bin/bash\\")"',
            'ruby': 'ruby -e "exec \\"/bin/bash\\""',
            'lua': 'lua -e "os.execute(\\"/bin/bash\\")"',
            'node': 'node -e "require(\\"child_process\\").spawn(\\"/bin/bash\\")"',
            'tar': 'tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
            'zip': 'zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c /bin/bash"',
            'git': 'git help status → !/bin/bash',
            'ftp': 'ftp → !/bin/bash',
            'gdb': 'gdb -nx -ex "!sh" -ex quit',
            'strace': 'strace -o /dev/null /bin/bash',
        }
        
        if suid_files:
            count = 0
            for line in suid_files.split('\n'):
                if line:
                    count += 1
                    binary_name = os.path.basename(line)
                    
                    if binary_name in dangerous_suid:
                        self.add_finding('critical', 'SUID', 
                                       f'Exploitable SUID binary found: {line}',
                                       f'Exploit: {dangerous_suid[binary_name]}')
                    elif count <= 10:  # Show first 10
                        print(f"  {Colors.GREEN}[+]{Colors.END} {line}")
            
            print(f"\n{Colors.CYAN}[*] Total SUID files found: {count}{Colors.END}")
            self.add_finding('info', 'SUID', f'Found {count} SUID files')
        
        # Find SGID files
        sgid_files = self.run_command("find / -perm -2000 -type f 2>/dev/null", shell=True)
        if sgid_files:
            sgid_count = len(sgid_files.split('\n'))
            print(f"{Colors.CYAN}[*] Total SGID files found: {sgid_count}{Colors.END}")
            self.add_finding('info', 'SGID', f'Found {sgid_count} SGID files')
    
    def check_writable_files(self):
        """Check for world-writable files and directories"""
        self.print_section("World-Writable Files & Directories")
        
        # Check /etc/passwd and /etc/shadow
        if os.access('/etc/passwd', os.W_OK):
            self.add_finding('critical', 'Writable File', 
                           '/etc/passwd is writable!',
                           'You can add a root user: echo "hacker:x:0:0::/root:/bin/bash" >> /etc/passwd')
        
        if os.access('/etc/shadow', os.W_OK):
            self.add_finding('critical', 'Writable File', 
                           '/etc/shadow is writable!',
                           'You can modify password hashes')
        
        # Check for writable directories in PATH
        path_dirs = os.environ.get('PATH', '').split(':')
        for directory in path_dirs:
            if os.path.exists(directory) and os.access(directory, os.W_OK):
                self.add_finding('high', 'Writable PATH', 
                               f'Writable directory in PATH: {directory}',
                               'You can place malicious binaries here')
        
        # Check common writable directories
        print(f"{Colors.CYAN}[*] Searching for world-writable directories...{Colors.END}")
        writable_dirs = self.run_command("find / -type d -perm -222 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -20", shell=True)
        
        if writable_dirs:
            for line in writable_dirs.split('\n'):
                if line and '/tmp' not in line and '/var/tmp' not in line:
                    print(f"  {Colors.YELLOW}[!]{Colors.END} {line}")
    
    def check_cron_jobs(self):
        """Check for cron jobs and scheduled tasks"""
        self.print_section("Cron Jobs & Scheduled Tasks")
        
        # User crontab
        user_cron = self.run_command("crontab -l 2>/dev/null", shell=True)
        if user_cron and "no crontab" not in user_cron.lower():
            print(f"{Colors.GREEN}[+] User crontab:{Colors.END}")
            print(user_cron)
            self.add_finding('info', 'Cron', 'User has crontab entries')
        
        # System crontabs
        cron_files = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/etc/cron.daily/',
            '/etc/cron.hourly/',
            '/etc/cron.monthly/',
            '/etc/cron.weekly/'
        ]
        
        for cron_file in cron_files:
            if os.path.exists(cron_file):
                if os.path.isdir(cron_file):
                    files = self.run_command(f"ls -la {cron_file}")
                    if files:
                        print(f"\n{Colors.GREEN}[+] {cron_file}:{Colors.END}")
                        print(files)
                else:
                    if os.access(cron_file, os.R_OK):
                        content = self.run_command(f"cat {cron_file}")
                        if content:
                            print(f"\n{Colors.GREEN}[+] {cron_file}:{Colors.END}")
                            print(content)
                            
                            # Check for writable cron scripts
                            if os.access(cron_file, os.W_OK):
                                self.add_finding('critical', 'Writable Cron', 
                                               f'Writable cron file: {cron_file}',
                                               'You can inject commands')
    
    def check_capabilities(self):
        """Check for file capabilities"""
        self.print_section("File Capabilities")
        
        print(f"{Colors.CYAN}[*] Searching for files with capabilities...{Colors.END}")
        
        cap_files = self.run_command("getcap -r / 2>/dev/null", shell=True)
        
        if cap_files:
            dangerous_caps = ['cap_setuid', 'cap_dac_override', 'cap_dac_read_search', 
                            'cap_sys_admin', 'cap_sys_ptrace']
            
            for line in cap_files.split('\n'):
                if line:
                    print(f"  {Colors.GREEN}[+]{Colors.END} {line}")
                    
                    for cap in dangerous_caps:
                        if cap in line:
                            self.add_finding('high', 'Capabilities', 
                                           f'Dangerous capability found: {line}',
                                           f'{cap} can be exploited for privilege escalation')
        else:
            print(f"{Colors.CYAN}[*] No files with capabilities found{Colors.END}")
    
    def check_services(self):
        """Check running services"""
        self.print_section("Running Services")
        
        # Check for services running as root
        processes = self.run_command("ps aux | grep -E '^root'")
        if processes:
            print(f"{Colors.CYAN}[*] Services running as root (sample):{Colors.END}")
            for line in processes.split('\n')[:10]:
                if line:
                    print(f"  {line}")
        
        # Check network services
        netstat = self.run_command("netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null", shell=True)
        if netstat:
            print(f"\n{Colors.GREEN}[+] Listening network services:{Colors.END}")
            for line in netstat.split('\n')[:15]:
                if 'LISTEN' in line or 'listen' in line.lower():
                    print(f"  {line}")
    
    def check_docker(self):
        """Check Docker privileges"""
        self.print_section("Docker & Container Escape")
        
        # Check if user is in docker group
        groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
        if 'docker' in groups:
            self.add_finding('critical', 'Docker', 
                           'User is in docker group!',
                           'You can escape to root: docker run -v /:/mnt --rm -it alpine chroot /mnt sh')
        
        # Check if running inside container
        if os.path.exists('/.dockerenv'):
            self.add_finding('high', 'Container', 
                           'Running inside Docker container',
                           'Check for container escape techniques')
        
        # Check for accessible docker socket
        if os.path.exists('/var/run/docker.sock'):
            if os.access('/var/run/docker.sock', os.W_OK):
                self.add_finding('critical', 'Docker Socket', 
                               'Docker socket is writable!',
                               'You can create privileged containers')
    
    def check_nfs_shares(self):
        """Check for NFS shares"""
        self.print_section("NFS Shares")
        
        nfs_exports = self.run_command("cat /etc/exports 2>/dev/null", shell=True)
        if nfs_exports:
            print(f"{Colors.GREEN}[+] NFS exports found:{Colors.END}")
            print(nfs_exports)
            
            if 'no_root_squash' in nfs_exports:
                self.add_finding('critical', 'NFS', 
                               'NFS share with no_root_squash found!',
                               'You can create SUID binaries on the share')
    
    def check_ssh_keys(self):
        """Check SSH keys and authorized_keys"""
        self.print_section("SSH Keys & Configuration")
        
        # Check authorized_keys
        ssh_dir = Path.home() / '.ssh'
        if ssh_dir.exists():
            auth_keys = ssh_dir / 'authorized_keys'
            if auth_keys.exists():
                print(f"{Colors.GREEN}[+] Authorized keys found:{Colors.END}")
                keys = self.run_command(f"cat {auth_keys}")
                print(keys)
                self.add_finding('info', 'SSH', 'SSH authorized_keys found')
            
            # Check for private keys
            for key_file in ssh_dir.glob('id_*'):
                if not key_file.name.endswith('.pub'):
                    print(f"{Colors.YELLOW}[!] Private key found: {key_file}{Colors.END}")
                    self.add_finding('medium', 'SSH', f'Private SSH key found: {key_file}')
        
        # Check SSH config for weak settings
        ssh_config = self.run_command("cat /etc/ssh/sshd_config 2>/dev/null", shell=True)
        if ssh_config:
            if 'PermitRootLogin yes' in ssh_config:
                self.add_finding('high', 'SSH Config', 
                               'Root login is permitted via SSH',
                               'PermitRootLogin yes in sshd_config')
            
            if 'PasswordAuthentication yes' in ssh_config:
                self.add_finding('medium', 'SSH Config', 
                               'Password authentication is enabled')
    
    def check_history_files(self):
        """Check command history for sensitive information"""
        self.print_section("Command History & Sensitive Files")
        
        history_files = [
            '.bash_history', '.zsh_history', '.sh_history', 
            '.mysql_history', '.psql_history'
        ]
        
        home = Path.home()
        for hist_file in history_files:
            hist_path = home / hist_file
            if hist_path.exists():
                print(f"{Colors.GREEN}[+] Found: {hist_path}{Colors.END}")
                
                # Search for passwords in history
                content = self.run_command(f"cat {hist_path}")
                if content:
                    sensitive_keywords = ['password', 'passwd', 'pwd', 'secret', 'token', 'api_key']
                    for keyword in sensitive_keywords:
                        if keyword in content.lower():
                            self.add_finding('high', 'Sensitive Data', 
                                           f'Keyword "{keyword}" found in {hist_file}',
                                           'Check history for credentials')
                            break
    
    def check_env_vars(self):
        """Check environment variables"""
        self.print_section("Environment Variables")
        
        # Check LD_PRELOAD
        if 'LD_PRELOAD' in os.environ:
            self.add_finding('high', 'Environment', 
                           'LD_PRELOAD is set!',
                           f'LD_PRELOAD={os.environ["LD_PRELOAD"]}')
        
        # Check PATH
        path = os.environ.get('PATH', '')
        print(f"{Colors.GREEN}[+] PATH:{Colors.END} {path}")
        
        if '.' in path.split(':'):
            self.add_finding('medium', 'Environment', 
                           'Current directory (.) is in PATH',
                           'This can be exploited with PATH hijacking')
        
        # Check for interesting variables
        interesting_vars = ['LD_LIBRARY_PATH', 'PYTHONPATH', 'PERL5LIB', 'NODE_PATH']
        for var in interesting_vars:
            if var in os.environ:
                print(f"{Colors.YELLOW}[!] {var}:{Colors.END} {os.environ[var]}")
    
    def print_summary(self):
        """Print summary of findings"""
        self.print_section("Summary of Findings")
        
        # Count by severity
        critical = len([f for f in self.findings if f['severity'] == 'critical'])
        high = len([f for f in self.findings if f['severity'] == 'high'])
        medium = len([f for f in self.findings if f['severity'] == 'medium'])
        low = len([f for f in self.findings if f['severity'] == 'low'])
        info = len([f for f in self.findings if f['severity'] == 'info'])
        
        print(f"{Colors.RED}  CRITICAL: {critical}{Colors.END}")
        print(f"{Colors.RED}  HIGH: {high}{Colors.END}")
        print(f"{Colors.YELLOW}  MEDIUM: {medium}{Colors.END}")
        print(f"{Colors.CYAN}  LOW: {low}{Colors.END}")
        print(f"{Colors.BLUE}  INFO: {info}{Colors.END}")
        
        print(f"\n{Colors.BOLD}Total Findings: {len(self.findings)}{Colors.END}\n")
        
        # Show critical findings
        critical_findings = [f for f in self.findings if f['severity'] == 'critical']
        if critical_findings:
            print(f"{Colors.RED}{Colors.BOLD}CRITICAL FINDINGS:{Colors.END}\n")
            for i, finding in enumerate(critical_findings, 1):
                print(f"{Colors.RED}[{i}] {finding['description']}{Colors.END}")
                if finding['details']:
                    print(f"    {finding['details']}\n")
    
    def run_full_enum(self):
        """Run full enumeration"""
        self.print_banner()
        
        # Check if root
        if self.current_uid == 0:
            print(f"{Colors.GREEN}[+] Already running as root!{Colors.END}\n")
            return
        
        # Run all checks
        self.check_system_info()
        self.check_sudo_privs()
        self.check_suid_files()
        self.check_writable_files()
        self.check_capabilities()
        self.check_cron_jobs()
        self.check_services()
        self.check_docker()
        self.check_nfs_shares()
        self.check_ssh_keys()
        self.check_history_files()
        self.check_env_vars()
        
        # Print summary
        self.print_summary()
        
        print(f"{Colors.CYAN}[*] Enumeration complete!{Colors.END}\n")

# ============================================================================
# MAIN
# ============================================================================
def main():
    # Check if running on Linux
    if os.name != 'posix':
        print(f"{Colors.RED}[!] This tool only works on Linux/Unix systems{Colors.END}")
        sys.exit(1)
    
    # Check if running as root
    if os.getuid() == 0:
        print(f"{Colors.YELLOW}[!] Running as root - enumeration may have limited value{Colors.END}")
    
    # Create checker instance
    checker = PrivEscChecker()
    
    try:
        checker.run_full_enum()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {str(e)}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
