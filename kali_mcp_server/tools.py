"""
Implementation of MCP tools for the Kali Linux environment.

This module contains the implementations of the tools exposed by the MCP server:
- fetch_website: Fetches content from a specified URL
- kali_terminal: Executes shell commands in the Kali Linux environment
- system_resources: Lists available system resources and command examples
"""

import asyncio
import json
import platform
import re
from typing import Sequence, Union, Optional
import os
import datetime

import httpx
import mcp.types as types

# List of allowed commands for security purposes
# Format: (command_prefix, is_long_running)
ALLOWED_COMMANDS = [
    # System information
    ("uname", False),
    ("whoami", False),
    ("id", False),
    ("uptime", False),
    ("date", False),
    ("free", False),
    ("df", False),
    ("ps", False),
    ("top -n 1", False),
    
    # Network utilities
    ("ping -c", False),  # Allow ping with count parameter
    ("ifconfig", False),
    ("ip", False),
    ("netstat", False),
    ("ss", False),
    ("dig", False),
    ("nslookup", False),
    ("host", False),
    ("curl", False),
    ("wget", False),
    
    # Security tools
    ("nmap", True),  # Long-running
    ("nikto", True),  # Long-running
    ("gobuster", True),  # Long-running
    ("dirb", True),  # Long-running
    ("whois", False),
    ("sqlmap", True),  # Long-running
    ("searchsploit", False),
    ("traceroute", False),
    ("testssl.sh", True),  # Long-running
    ("amass", True),  # Long-running
    ("httpx", True),  # Long-running
    ("subfinder", True),  # Long-running
    ("waybackurls", False),
    ("gospider", True),  # Long-running
    
    # File analysis tools
    ("file", False),
    ("strings", False),
    ("sha256sum", False),
    ("md5sum", False),
    ("wc", False),
    
    # File operations
    ("ls", False),
    # Only allow cat on safe files
    ("cat /proc/", False),
    ("cat /var/log/", False),
    ("cat command_output.txt", False),
    ("cat *.txt", False),
    ("cat *.log", False),
    ("cat vuln_scan_", False),
    ("cat web_enum_", False),
    ("cat network_discovery_", False),
    ("cat exploit_search_", False),
    ("cat file_analysis_", False),
    ("cat report_", False),
    ("cat downloads/", False),
    ("cat spider_", False),
    ("cat form_analysis_", False),
    ("cat header_analysis_", False),
    ("cat ssl_analysis_", False),
    ("cat subdomain_enum_", False),
    ("cat web_audit_", False),
    ("head", False),
    ("tail", False),
    ("find", True),  # Can be long-running
    ("grep", False),
    
    # Utility commands
    ("echo", False),
    ("which", False),
    ("man", False),
    ("help", False),
]

# --- Session Management Backend ---
SESSIONS_DIR = "sessions"
ACTIVE_SESSION_FILE = os.path.join(SESSIONS_DIR, "active_session.txt")


def ensure_sessions_dir():
    os.makedirs(SESSIONS_DIR, exist_ok=True)


def get_session_path(session_name):
    return os.path.join(SESSIONS_DIR, session_name)


def get_session_metadata_path(session_name):
    return os.path.join(get_session_path(session_name), "metadata.json")


def list_sessions():
    ensure_sessions_dir()
    return [d for d in os.listdir(SESSIONS_DIR) if os.path.isdir(get_session_path(d))]


def save_active_session(session_name):
    ensure_sessions_dir()
    with open(ACTIVE_SESSION_FILE, "w") as f:
        f.write(session_name)


def load_active_session():
    try:
        with open(ACTIVE_SESSION_FILE, "r") as f:
            return f.read().strip()
    except Exception:
        return None


def create_session(session_name, description, target):
    ensure_sessions_dir()
    session_dir = get_session_path(session_name)
    if os.path.exists(session_dir):
        raise ValueError(f"Session '{session_name}' already exists.")
    os.makedirs(session_dir)
    metadata = {
        "name": session_name,
        "description": description,
        "target": target,
        "created": datetime.datetime.now().isoformat(),
        "history": []
    }
    with open(get_session_metadata_path(session_name), "w") as f:
        json.dump(metadata, f, indent=2)
    save_active_session(session_name)
    return metadata

# --- Session Management Tools ---

async def session_create(session_name: str, description: str = "", target: str = "") -> list:
    """
    Create a new pentest session.
    Args:
        session_name: Name of the session
        description: Description of the session
        target: Target for the session
    Returns:
        List containing TextContent with session creation result
    """
    try:
        metadata = create_session(session_name, description, target)
        return [types.TextContent(type="text", text=f"✅ Session '{session_name}' created and set as active.\n\nDescription: {description}\nTarget: {target}\nCreated: {metadata['created']}")]
    except ValueError as e:
        return [types.TextContent(type="text", text=f"❌ {str(e)}")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error creating session: {str(e)}")]


async def session_list() -> list:
    """
    List all pentest sessions with metadata.
    Returns:
        List containing TextContent with session list
    """
    try:
        sessions = list_sessions()
        active_session = load_active_session()
        
        if not sessions:
            return [types.TextContent(type="text", text="📋 No sessions found. Use /session_create to create a new session.")]
        
        output = "📋 Available Sessions:\n\n"
        
        for session_name in sessions:
            try:
                with open(get_session_metadata_path(session_name), 'r') as f:
                    metadata = json.load(f)
                
                status = "🟢 ACTIVE" if session_name == active_session else "⚪ INACTIVE"
                output += f"## {session_name} {status}\n"
                output += f"**Description:** {metadata.get('description', 'No description')}\n"
                output += f"**Target:** {metadata.get('target', 'No target')}\n"
                output += f"**Created:** {metadata.get('created', 'Unknown')}\n"
                output += f"**History Items:** {len(metadata.get('history', []))}\n\n"
                
            except Exception as e:
                output += f"## {session_name} ⚠️ ERROR\n"
                output += f"Could not load metadata: {str(e)}\n\n"
        
        if active_session:
            output += f"🟢 **Active Session:** {active_session}"
        else:
            output += "⚠️ **No active session**"
        
        return [types.TextContent(type="text", text=output)]
        
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error listing sessions: {str(e)}")]


async def session_switch(session_name: str) -> list:
    """
    Switch to a different pentest session.
    Args:
        session_name: Name of the session to switch to
    Returns:
        List containing TextContent with switch result
    """
    try:
        sessions = list_sessions()
        if session_name not in sessions:
            return [types.TextContent(type="text", text=f"❌ Session '{session_name}' not found. Available sessions: {', '.join(sessions)}")]
        
        save_active_session(session_name)
        
        # Load session metadata for confirmation
        try:
            with open(get_session_metadata_path(session_name), 'r') as f:
                metadata = json.load(f)
            
            return [types.TextContent(type="text", text=
                f"✅ Switched to session '{session_name}'\n\n"
                f"**Description:** {metadata.get('description', 'No description')}\n"
                f"**Target:** {metadata.get('target', 'No target')}\n"
                f"**Created:** {metadata.get('created', 'Unknown')}\n"
                f"**History Items:** {len(metadata.get('history', []))}"
            )]
        except Exception as e:
            return [types.TextContent(type="text", text=f"✅ Switched to session '{session_name}' (metadata could not be loaded: {str(e)})")]
            
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error switching sessions: {str(e)}")]


async def session_status() -> list:
    """
    Show current session status and summary.
    Returns:
        List containing TextContent with current session status
    """
    try:
        active_session = load_active_session()
        
        if not active_session:
            return [types.TextContent(type="text", text="⚠️ No active session. Use /session_create to create a new session or /session_switch to switch to an existing one.")]
        
        # Load session metadata
        try:
            with open(get_session_metadata_path(active_session), 'r') as f:
                metadata = json.load(f)
            
            # Count files in session directory
            session_dir = get_session_path(active_session)
            file_count = 0
            if os.path.exists(session_dir):
                file_count = len([f for f in os.listdir(session_dir) if os.path.isfile(os.path.join(session_dir, f)) and f != "metadata.json"])
            
            output = f"🟢 **Active Session:** {active_session}\n\n"
            output += f"**Description:** {metadata.get('description', 'No description')}\n"
            output += f"**Target:** {metadata.get('target', 'No target')}\n"
            output += f"**Created:** {metadata.get('created', 'Unknown')}\n"
            output += f"**History Items:** {len(metadata.get('history', []))}\n"
            output += f"**Session Files:** {file_count}\n\n"
            
            # Show recent history (last 5 items)
            history = metadata.get('history', [])
            if history:
                output += "**Recent Activity:**\n"
                for item in history[-5:]:
                    output += f"- {item.get('timestamp', 'Unknown')}: {item.get('action', 'Unknown action')}\n"
            else:
                output += "**Recent Activity:** No activity recorded yet."
            
            return [types.TextContent(type="text", text=output)]
            
        except Exception as e:
            return [types.TextContent(type="text", text=f"⚠️ Active session '{active_session}' found, but metadata could not be loaded: {str(e)}")]
            
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error getting session status: {str(e)}")]


async def session_delete(session_name: str) -> list:
    """
    Delete a pentest session and all its evidence.
    Args:
        session_name: Name of the session to delete
    Returns:
        List containing TextContent with deletion result
    """
    try:
        sessions = list_sessions()
        if session_name not in sessions:
            return [types.TextContent(type="text", text=f"❌ Session '{session_name}' not found. Available sessions: {', '.join(sessions)}")]
        
        active_session = load_active_session()
        
        # Check if trying to delete active session
        if session_name == active_session:
            return [types.TextContent(type="text", text=f"❌ Cannot delete active session '{session_name}'. Switch to another session first using /session_switch.")]
        
        # Load metadata before deletion for confirmation
        try:
            with open(get_session_metadata_path(session_name), 'r') as f:
                metadata = json.load(f)
            
            description = metadata.get('description', 'No description')
            target = metadata.get('target', 'No target')
            created = metadata.get('created', 'Unknown')
            history_count = len(metadata.get('history', []))
            
        except Exception:
            description = "Unknown"
            target = "Unknown"
            created = "Unknown"
            history_count = 0
        
        # Delete session directory and all contents
        session_dir = get_session_path(session_name)
        import shutil
        shutil.rmtree(session_dir)
        
        return [types.TextContent(type="text", text=
            f"✅ Session '{session_name}' deleted successfully.\n\n"
            f"**Deleted Session Details:**\n"
            f"- Description: {description}\n"
            f"- Target: {target}\n"
            f"- Created: {created}\n"
            f"- History Items: {history_count}\n"
            f"- All session files and evidence have been removed."
        )]
        
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error deleting session: {str(e)}")]


async def session_history() -> list:
    """
    Show command/evidence history for the current session.
    Returns:
        List containing TextContent with session history
    """
    try:
        active_session = load_active_session()
        
        if not active_session:
            return [types.TextContent(type="text", text="⚠️ No active session. Use /session_create to create a new session or /session_switch to switch to an existing one.")]
        
        # Load session metadata
        try:
            with open(get_session_metadata_path(active_session), 'r') as f:
                metadata = json.load(f)
            
            history = metadata.get('history', [])
            
            if not history:
                return [types.TextContent(type="text", text=f"📜 No history recorded for session '{active_session}' yet.")]
            
            output = f"📜 **Session History for '{active_session}'**\n\n"
            output += f"**Total Items:** {len(history)}\n\n"
            
            # Show all history items in reverse chronological order
            for i, item in enumerate(reversed(history), 1):
                timestamp = item.get('timestamp', 'Unknown')
                action = item.get('action', 'Unknown action')
                details = item.get('details', '')
                
                output += f"**{len(history) - i + 1}.** {timestamp}\n"
                output += f"   **Action:** {action}\n"
                if details:
                    output += f"   **Details:** {details}\n"
                output += "\n"
            
            return [types.TextContent(type="text", text=output)]
            
        except Exception as e:
            return [types.TextContent(type="text", text=f"⚠️ Could not load history for session '{active_session}': {str(e)}")]
            
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error getting session history: {str(e)}")]


async def fetch_website(url: str) -> Sequence[Union[types.TextContent, types.ImageContent, types.EmbeddedResource]]:
    """
    Fetch content from a specified URL.
    
    Args:
        url: The URL to fetch content from
        
    Returns:
        List containing TextContent with the website content
        
    Raises:
        ValueError: If the URL is invalid
        httpx.HTTPError: If the request fails
    """
    # Basic URL validation
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    
    # Set user agent to identify the client
    headers = {
        "User-Agent": "Kali MCP Server (github.com/modelcontextprotocol/python-sdk)"
    }
    
    # Fetch the URL with timeout and redirect following
    async with httpx.AsyncClient(
        follow_redirects=True, 
        headers=headers,
        timeout=30.0
    ) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            return [types.TextContent(type="text", text=response.text)]
        except httpx.TimeoutException:
            return [types.TextContent(type="text", text="Request timed out after 30 seconds")]
        except httpx.HTTPStatusError as e:
            return [types.TextContent(type="text", text=f"HTTP error: {e.response.status_code} - {e.response.reason_phrase}")]
        except httpx.RequestError as e:
            return [types.TextContent(type="text", text=f"Request error: {str(e)}")]


def is_command_allowed(command: str) -> tuple[bool, bool]:
    """
    Check if a command is allowed to run and if it's potentially long-running.
    
    Args:
        command: The shell command to check
        
    Returns:
        Tuple of (is_allowed, is_long_running)
    """
    # Clean the command for checking
    clean_command = command.strip().lower()
    
    # Check against the allowed commands list
    for allowed_prefix, is_long_running in ALLOWED_COMMANDS:
        if clean_command.startswith(allowed_prefix):
            return True, is_long_running
    
    return False, False


async def run_command(command: str) -> Sequence[types.TextContent]:
    """
    Execute a shell command in the Kali Linux environment.
    
    Args:
        command: The shell command to execute
        
    Returns:
        List containing TextContent with the command output
        
    Notes:
        - Long-running commands are executed in the background
        - Commands are checked against an allowlist for security
    """
    try:
        # Sanitize the command (basic security measure)
        # Remove potentially dangerous characters
        command = re.sub(r'[;&|]', '', command)
        
        # Check if command is allowed
        is_allowed, is_long_running = is_command_allowed(command)
        
        if not is_allowed:
            return [types.TextContent(type="text", text=
                f"Command '{command}' is not allowed for security reasons. "
                f"Please use one of the permitted commands or tools."
            )]
        
        # For long-running commands, run them in the background
        if is_long_running:
            process = await asyncio.create_subprocess_shell(
                f"{command} > command_output.txt 2>&1 &",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            return [types.TextContent(type="text", text=
                f"Running command '{command}' in background. Output will be saved to command_output.txt.\n"
                f"You can view results later with 'cat command_output.txt'"
            )]
        
        # For regular commands, use a timeout approach
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Wait for command to complete with timeout
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60.0)
            
            output = stdout.decode() if stdout else ""
            error = stderr.decode() if stderr else ""
            
            if error:
                output += f"\nErrors:\n{error}"
                
            return [types.TextContent(type="text", text=output or "Command executed successfully (no output)")]
        except asyncio.TimeoutError:
            # Kill process if it's taking too long
            process.kill()
            return [types.TextContent(type="text", text=
                "Command timed out after 60 seconds. For long-running commands, "
                "try adding '> output.txt &' to run in background."
            )]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error executing command: {str(e)}")]


async def list_system_resources() -> Sequence[types.TextContent]:
    """
    List available system resources and provide command examples.
    
    Returns:
        List containing TextContent with system resources information
    """
    # Get system information
    system_info = {
        "os": platform.system(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "hostname": platform.node()
    }
    
    # Define categories of commands with examples
    resources = {
        "system_info": {
            "description": "Commands to gather system information",
            "commands": {
                "uname -a": "Display kernel information",
                "top -n 1": "Show running processes and resource usage",
                "df -h": "Display disk space usage",
                "free -m": "Show memory usage",
                "uptime": "Display system uptime",
                "ps aux": "List all running processes"
            }
        },
        "network": {
            "description": "Network diagnostic and scanning tools",
            "commands": {
                "ifconfig": "Display network interfaces",
                "ping -c 4 google.com": "Test network connectivity",
                "curl https://example.com": "Fetch content from a URL",
                "netstat -tuln": "Show listening ports",
                "nmap -F 127.0.0.1": "Quick network scan (background)",
                "dig example.com": "DNS lookup"
            }
        },
        "security_tools": {
            "description": "Security and penetration testing tools",
            "commands": {
                "nmap -sV -p1-1000 127.0.0.1": "Service version detection scan",
                "nikto -h 127.0.0.1": "Web server security scanner",
                "gobuster dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt": "Directory enumeration",
                "whois example.com": "Domain registration information",
                "sqlmap --url http://example.com --dbs": "SQL injection testing",
                "searchsploit apache": "Search for Apache exploits",
                "traceroute example.com": "Trace network route to target"
            }
        },
        "enhanced_tools": {
            "description": "Enhanced security analysis tools (new)",
            "commands": {
                "/vulnerability_scan target=127.0.0.1 scan_type=quick": "Quick vulnerability assessment",
                "/vulnerability_scan target=127.0.0.1 scan_type=comprehensive": "Comprehensive vulnerability scan",
                "/web_enumeration target=http://example.com enumeration_type=full": "Full web application enumeration",
                "/network_discovery target=192.168.1.0/24 discovery_type=comprehensive": "Network discovery and mapping",
                "/exploit_search search_term=apache search_type=web": "Search for web exploits"
            }
        },
        "file_management": {
            "description": "File management and evidence collection tools (new)",
            "commands": {
                "/save_output content='scan results' filename=my_scan category=scan": "Save content to timestamped file",
                "/create_report title='Security Assessment' findings='Vulnerabilities found' report_type=markdown": "Generate structured report",
                "/file_analysis filepath=./suspicious_file": "Analyze file with multiple tools",
                "/download_file url=https://example.com/file.txt filename=downloaded_file": "Download file from URL"
            }
        },
        "file_operations": {
            "description": "File and directory operations",
            "commands": {
                "ls -la": "List files with details",
                "find . -name '*.py'": "Find Python files in current directory",
                "grep 'pattern' file.txt": "Search for text in a file",
                "cat file.txt": "Display file contents",
                "head -n 10 file.txt": "Show first 10 lines of a file",
                "tail -f logfile.txt": "Follow log file updates"
            }
        },
        "utilities": {
            "description": "Useful utility commands",
            "commands": {
                "date": "Show current date and time",
                "cal": "Display calendar",
                "which command": "Find path to a command",
                "echo $PATH": "Display PATH environment variable",
                "history": "Show command history"
            }
        },
        "background_execution": {
            "description": "Run commands in background and check results",
            "commands": {
                "command > output.txt 2>&1 &": "Run any command in background",
                "cat output.txt": "View output from background commands",
                "jobs": "List background jobs",
                "nohup command &": "Run command immune to hangups"
            }
        }
    }
    
    # Format output with Markdown
    output = "# System Resources\n\n## System Information\n"
    output += json.dumps(system_info, indent=2) + "\n\n"
    
    # Add each category
    for category, data in resources.items():
        output += f"## {category.replace('_', ' ').title()}\n"
        output += f"{data['description']}\n\n"
        
        # Add commands in category
        output += "| Command | Description |\n"
        output += "|---------|-------------|\n"
        for cmd, desc in data["commands"].items():
            output += f"| `{cmd}` | {desc} |\n"
        
        output += "\n"
    
    return [types.TextContent(type="text", text=output)]


async def vulnerability_scan(target: str, scan_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """
    Perform automated vulnerability assessment with multiple tools.
    
    Args:
        target: Target IP address or hostname
        scan_type: Type of scan (quick, comprehensive, web, network)
        
    Returns:
        List containing TextContent with scan results
    """
    timestamp = asyncio.get_event_loop().time()
    output_file = f"vuln_scan_{target.replace('.', '_')}_{int(timestamp)}.txt"
    
    scan_commands = []
    
    if scan_type == "quick":
        scan_commands = [
            f"nmap -F -sV {target}",
            f"nikto -h {target} -Format txt -o {output_file}"
        ]
    elif scan_type == "comprehensive":
        scan_commands = [
            f"nmap -sS -sV -O -p- {target}",
            f"nikto -h {target} -Format txt -o {output_file}",
            f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -o {output_file}_dirs",
            f"whois {target}"
        ]
    elif scan_type == "web":
        scan_commands = [
            f"nikto -h {target} -Format txt -o {output_file}",
            f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -o {output_file}_dirs",
            f"sqlmap --url http://{target} --batch --random-agent --level 1"
        ]
    elif scan_type == "network":
        scan_commands = [
            f"nmap -sS -sV -O -p- {target}",
            f"nmap --script vuln {target}",
            f"whois {target}"
        ]
    
    # Execute all commands in background
    for cmd in scan_commands:
        process = await asyncio.create_subprocess_shell(
            f"{cmd} >> {output_file} 2>&1 &",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
    
    return [types.TextContent(type="text", text=
        f"🚀 Starting {scan_type} vulnerability scan on {target}\n\n"
        f"📋 Commands being executed:\n"
        f"{chr(10).join(f'• {cmd}' for cmd in scan_commands)}\n\n"
        f"📁 Results will be saved to: {output_file}\n"
        f"⏱️  Check progress with: cat {output_file}\n"
        f"🔍 Monitor processes with: ps aux | grep -E '(nmap|nikto|gobuster|sqlmap)'"
    )]


async def web_enumeration(target: str, enumeration_type: str = "full") -> Sequence[types.TextContent]:
    """
    Perform comprehensive web application discovery and enumeration.
    
    Args:
        target: Target URL (e.g., http://example.com)
        enumeration_type: Type of enumeration (basic, full, aggressive)
        
    Returns:
        List containing TextContent with enumeration results
    """
    timestamp = asyncio.get_event_loop().time()
    output_file = f"web_enum_{target.replace('://', '_').replace('/', '_')}_{int(timestamp)}.txt"
    
    # Ensure target has protocol
    if not target.startswith(('http://', 'https://')):
        target = f"http://{target}"
    
    enum_commands = []
    
    if enumeration_type == "basic":
        enum_commands = [
            f"nikto -h {target} -Format txt -o {output_file}",
            f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -o {output_file}_dirs"
        ]
    elif enumeration_type == "full":
        enum_commands = [
            f"nikto -h {target} -Format txt -o {output_file}",
            f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -o {output_file}_dirs",
            f"gobuster vhost -u {target} -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o {output_file}_vhosts",
            f"curl -I {target}",
            f"curl -s {target} | grep -i 'server\\|powered-by\\|x-'"
        ]
    elif enumeration_type == "aggressive":
        enum_commands = [
            f"nikto -h {target} -Format txt -o {output_file}",
            f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -o {output_file}_dirs",
            f"gobuster vhost -u {target} -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o {output_file}_vhosts",
            f"sqlmap --url {target} --batch --random-agent --level 2",
            f"dirb {target} /usr/share/wordlists/dirb/common.txt -o {output_file}_dirb"
        ]
    
    # Execute commands
    for cmd in enum_commands:
        process = await asyncio.create_subprocess_shell(
            f"{cmd} >> {output_file} 2>&1 &",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
    
    return [types.TextContent(type="text", text=
        f"🌐 Starting {enumeration_type} web enumeration on {target}\n\n"
        f"🔍 Enumeration tasks:\n"
        f"{chr(10).join(f'• {cmd}' for cmd in enum_commands)}\n\n"
        f"📁 Results will be saved to: {output_file}\n"
        f"⏱️  Check progress with: cat {output_file}\n"
        f"📊 Monitor with: tail -f {output_file}"
    )]


async def network_discovery(target: str, discovery_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """
    Perform multi-stage network reconnaissance and discovery.
    
    Args:
        target: Target network (e.g., 192.168.1.0/24) or host
        discovery_type: Type of discovery (quick, comprehensive, stealth)
        
    Returns:
        List containing TextContent with discovery results
    """
    timestamp = asyncio.get_event_loop().time()
    output_file = f"network_discovery_{target.replace('/', '_')}_{int(timestamp)}.txt"
    
    discovery_commands = []
    
    if discovery_type == "quick":
        discovery_commands = [
            f"nmap -sn {target}",
            f"nmap -F {target}",
            f"ping -c 3 {target}"
        ]
    elif discovery_type == "comprehensive":
        discovery_commands = [
            f"nmap -sn {target}",
            f"nmap -sS -sV -O -p- {target}",
            f"nmap --script discovery {target}",
            f"ping -c 5 {target}",
            f"traceroute {target}"
        ]
    elif discovery_type == "stealth":
        discovery_commands = [
            f"nmap -sS -sV --version-intensity 0 -p 80,443,22,21,25,53 {target}",
            f"nmap --script default {target}",
            f"ping -c 2 {target}"
        ]
    
    # Execute commands
    for cmd in discovery_commands:
        process = await asyncio.create_subprocess_shell(
            f"{cmd} >> {output_file} 2>&1 &",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
    
    return [types.TextContent(type="text", text=
        f"🔍 Starting {discovery_type} network discovery on {target}\n\n"
        f"🌐 Discovery tasks:\n"
        f"{chr(10).join(f'• {cmd}' for cmd in discovery_commands)}\n\n"
        f"📁 Results will be saved to: {output_file}\n"
        f"⏱️  Check progress with: cat {output_file}\n"
        f"📊 Monitor with: tail -f {output_file}"
    )]


async def exploit_search(search_term: str, search_type: str = "all") -> Sequence[types.TextContent]:
    """
    Search for exploits using searchsploit and other exploit databases.
    
    Args:
        search_term: Term to search for (e.g., "apache", "ssh", "CVE-2021-44228")
        search_type: Type of search (all, web, remote, local, dos)
        
    Returns:
        List containing TextContent with search results
    """
    timestamp = asyncio.get_event_loop().time()
    output_file = f"exploit_search_{search_term.replace(' ', '_')}_{int(timestamp)}.txt"
    
    search_commands = []
    
    if search_type == "all":
        search_commands = [
            f"searchsploit {search_term}",
            f"searchsploit {search_term} --exclude=/dos/"
        ]
    elif search_type == "web":
        search_commands = [
            f"searchsploit {search_term} web",
            f"searchsploit {search_term} --type web"
        ]
    elif search_type == "remote":
        search_commands = [
            f"searchsploit {search_term} remote",
            f"searchsploit {search_term} --type remote"
        ]
    elif search_type == "local":
        search_commands = [
            f"searchsploit {search_term} local",
            f"searchsploit {search_term} --type local"
        ]
    elif search_type == "dos":
        search_commands = [
            f"searchsploit {search_term} dos",
            f"searchsploit {search_term} --type dos"
        ]
    
    # Execute search commands
    for cmd in search_commands:
        process = await asyncio.create_subprocess_shell(
            f"{cmd} >> {output_file} 2>&1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
    
    # Read results
    try:
        with open(output_file, 'r') as f:
            results = f.read()
    except FileNotFoundError:
        results = "No results found or file not created."
    
    return [types.TextContent(type="text", text=
        f"🔍 Exploit search results for '{search_term}' ({search_type}):\n\n"
        f"📁 Results saved to: {output_file}\n\n"
        f"🔎 Search results:\n{results}"
    )]


async def save_output(content: str, filename: Optional[str] = None, category: str = "general") -> Sequence[types.TextContent]:
    """
    Save content to a timestamped file for evidence collection.
    
    Args:
        content: Content to save
        filename: Optional custom filename (without extension)
        category: Category for organizing files (e.g., "scan", "enum", "evidence")
        
    Returns:
        List containing TextContent with save confirmation
    """
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if filename:
        # Sanitize filename
        safe_filename = "".join(c for c in filename if c.isalnum() or c in ('-', '_')).rstrip()
        output_file = f"{category}_{safe_filename}_{timestamp}.txt"
    else:
        output_file = f"{category}_output_{timestamp}.txt"
    
    try:
        with open(output_file, 'w') as f:
            f.write(f"# {category.upper()} OUTPUT\n")
            f.write(f"Generated: {datetime.datetime.now().isoformat()}\n")
            f.write(f"File: {output_file}\n")
            f.write("-" * 50 + "\n\n")
            f.write(content)
        
        return [types.TextContent(type="text", text=
            f"✅ Content saved successfully!\n\n"
            f"📁 File: {output_file}\n"
            f"📊 Size: {len(content)} characters\n"
            f"🕒 Timestamp: {datetime.datetime.now().isoformat()}\n\n"
            f"📝 Preview (first 200 chars):\n{content[:200]}{'...' if len(content) > 200 else ''}"
        )]
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error saving file: {str(e)}")]


async def create_report(title: str, findings: str, report_type: str = "markdown") -> Sequence[types.TextContent]:
    """
    Generate a structured report from findings.
    
    Args:
        title: Report title
        findings: Findings content
        report_type: Type of report (markdown, text, json)
        
    Returns:
        List containing TextContent with report content and file location
    """
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_title = "".join(c for c in title if c.isalnum() or c in ('-', '_', ' ')).rstrip()
    report_file = f"report_{safe_title.replace(' ', '_')}_{timestamp}.{report_type}"
    
    try:
        if report_type == "markdown":
            report_content = f"""# {title}

**Generated:** {datetime.datetime.now().isoformat()}  
**Report File:** {report_file}

---

## Executive Summary

This report contains findings from security assessment activities.

---

## Findings

{findings}

---

## Recommendations

*Review findings and implement appropriate security measures.*

---

**Report generated by Kali MCP Server**  
*Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*
"""
        elif report_type == "text":
            report_content = f"""SECURITY ASSESSMENT REPORT
{'=' * 50}

Title: {title}
Generated: {datetime.datetime.now().isoformat()}
Report File: {report_file}

FINDINGS
{'-' * 20}

{findings}

RECOMMENDATIONS
{'-' * 20}

Review findings and implement appropriate security measures.

Report generated by Kali MCP Server
Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
        elif report_type == "json":
            import json
            report_data = {
                "title": title,
                "generated": datetime.datetime.now().isoformat(),
                "report_file": report_file,
                "findings": findings,
                "recommendations": "Review findings and implement appropriate security measures."
            }
            report_content = json.dumps(report_data, indent=2)
        else:
            return [types.TextContent(type="text", text=f"❌ Unsupported report type: {report_type}")]
        
        # Save report to file
        with open(report_file, 'w') as f:
            f.write(report_content)
        
        return [types.TextContent(type="text", text=
            f"📋 Report generated successfully!\n\n"
            f"📁 File: {report_file}\n"
            f"📊 Size: {len(report_content)} characters\n"
            f"🕒 Generated: {datetime.datetime.now().isoformat()}\n\n"
            f"📝 Report Preview:\n{report_content[:500]}{'...' if len(report_content) > 500 else ''}"
        )]
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error generating report: {str(e)}")]


async def file_analysis(filepath: str) -> Sequence[types.TextContent]:
    """
    Analyze a file using various tools (file type, strings, hash).
    
    Args:
        filepath: Path to the file to analyze
        
    Returns:
        List containing TextContent with analysis results
    """
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_filename = "".join(c for c in filepath.split('/')[-1] if c.isalnum() or c in ('-', '_', '.')).rstrip()
    analysis_file = f"file_analysis_{safe_filename}_{timestamp}.txt"
    
    analysis_commands = [
        f"file {filepath}",
        f"strings {filepath} | head -50",
        f"sha256sum {filepath}",
        f"ls -la {filepath}",
        f"wc -l {filepath}",
        f"head -10 {filepath}"
    ]
    
    analysis_results = []
    
    for cmd in analysis_commands:
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30.0)
            
            output = stdout.decode() if stdout else ""
            error = stderr.decode() if stderr else ""
            
            if output:
                analysis_results.append(f"## {cmd}\n{output}")
            if error:
                analysis_results.append(f"## {cmd} (ERROR)\n{error}")
        except asyncio.TimeoutError:
            analysis_results.append(f"## {cmd}\nTIMEOUT - Command took too long")
        except Exception as e:
            analysis_results.append(f"## {cmd}\nERROR - {str(e)}")
    
    # Combine all results
    full_analysis = f"""# FILE ANALYSIS REPORT

**File:** {filepath}  
**Analyzed:** {datetime.datetime.now().isoformat()}  
**Analysis File:** {analysis_file}

---

{chr(10).join(analysis_results)}

---

**Analysis completed by Kali MCP Server**
"""
    
    # Save analysis to file
    try:
        with open(analysis_file, 'w') as f:
            f.write(full_analysis)
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error saving analysis: {str(e)}")]
    
    return [types.TextContent(type="text", text=
        f"🔍 File analysis completed!\n\n"
        f"📁 Analysis saved to: {analysis_file}\n"
        f"📊 Analysis size: {len(full_analysis)} characters\n"
        f"🕒 Analyzed: {datetime.datetime.now().isoformat()}\n\n"
        f"📝 Analysis Preview:\n{full_analysis[:500]}{'...' if len(full_analysis) > 500 else ''}"
    )]


async def download_file(url: str, filename: Optional[str] = None) -> Sequence[types.TextContent]:
    """
    Download a file from a URL and save it locally.
    
    Args:
        url: URL to download from
        filename: Optional custom filename
        
    Returns:
        List containing TextContent with download status
    """
    import datetime
    import os
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if not filename:
        # Extract filename from URL
        filename = url.split('/')[-1] if '/' in url else f"downloaded_{timestamp}"
        if '?' in filename:
            filename = filename.split('?')[0]
    
    # Sanitize filename
    safe_filename = "".join(c for c in filename if c.isalnum() or c in ('-', '_', '.')).rstrip()
    if not safe_filename:
        safe_filename = f"downloaded_{timestamp}"
    
    download_path = f"downloads/{safe_filename}"
    
    # Create downloads directory if it doesn't exist
    os.makedirs("downloads", exist_ok=True)
    
    try:
        # Download file
        headers = {
            "User-Agent": "Kali MCP Server (github.com/modelcontextprotocol/python-sdk)"
        }
        
        async with httpx.AsyncClient(
            follow_redirects=True,
            headers=headers,
            timeout=60.0
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
            
            # Save file
            with open(download_path, 'wb') as f:
                f.write(response.content)
            
            # Get file info
            file_size = len(response.content)
            content_type = response.headers.get('content-type', 'unknown')
            
            # Generate hash
            import hashlib
            file_hash = hashlib.sha256(response.content).hexdigest()
            
            return [types.TextContent(type="text", text=
                f"✅ File downloaded successfully!\n\n"
                f"📁 Saved as: {download_path}\n"
                f"📊 Size: {file_size} bytes\n"
                f"🔗 URL: {url}\n"
                f"📋 Content-Type: {content_type}\n"
                f"🔐 SHA256: {file_hash}\n"
                f"🕒 Downloaded: {datetime.datetime.now().isoformat()}\n\n"
                f"💡 You can now analyze this file using the file_analysis tool."
            )]
    except httpx.TimeoutException:
        return [types.TextContent(type="text", text="❌ Download timed out after 60 seconds")]
    except httpx.HTTPStatusError as e:
        return [types.TextContent(type="text", text=f"❌ HTTP error: {e.response.status_code} - {e.response.reason_phrase}")]
    except httpx.RequestError as e:
        return [types.TextContent(type="text", text=f"❌ Request error: {str(e)}")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error downloading file: {str(e)}")]


# --- Enhanced Web Application Testing Tools ---

async def spider_website(url: str, depth: int = 2, threads: int = 10) -> Sequence[types.TextContent]:
    """
    Perform comprehensive web crawling and spidering.
    
    Args:
        url: Target URL to spider
        depth: Crawling depth (default: 2)
        threads: Number of concurrent threads (default: 10)
        
    Returns:
        List containing TextContent with spidering results
    """
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"spider_{safe_url}_{timestamp}.txt"
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    try:
        # Use gospider for comprehensive crawling
        spider_cmd = f"gospider -s {url} -d {depth} -c {threads} -o {output_file}"
        
        process = await asyncio.create_subprocess_shell(
            spider_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300.0)
        
        # Read results
        results = "Spidering completed"
        try:
            with open(output_file, 'r') as f:
                results = f.read()
        except (FileNotFoundError, IsADirectoryError):
            results = "Spidering completed - results may be in separate files"
        
        return [types.TextContent(type="text", text=
            f"🕷️ Website spidering completed!\n\n"
            f"🎯 Target: {url}\n"
            f"📊 Depth: {depth}\n"
            f"🧵 Threads: {threads}\n"
            f"📁 Results saved to: {output_file}\n"
            f"🕒 Completed: {datetime.datetime.now().isoformat()}\n\n"
            f"📝 Results Preview:\n{results[:500]}{'...' if len(results) > 500 else ''}"
        )]
    except asyncio.TimeoutError:
        return [types.TextContent(type="text", text="❌ Spidering timed out after 5 minutes")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error during spidering: {str(e)}")]


async def form_analysis(url: str, scan_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """
    Discover and analyze web forms for security testing.
    
    Args:
        url: Target URL to analyze
        scan_type: Type of analysis (basic, comprehensive, aggressive)
        
    Returns:
        List containing TextContent with form analysis results
    """
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"form_analysis_{safe_url}_{timestamp}.txt"
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    try:
        # Use httpx-toolkit for form discovery
        if scan_type == "basic":
            form_cmd = f"httpx -u {url} -mc 200 -silent -o {output_file}"
        elif scan_type == "comprehensive":
            form_cmd = f"httpx -u {url} -mc 200,301,302,403 -silent -o {output_file}"
        else:  # aggressive
            form_cmd = f"httpx -u {url} -mc all -silent -o {output_file}"
        
        process = await asyncio.create_subprocess_shell(
            form_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=180.0)
        
        # Additional form analysis with curl
        curl_cmd = f"curl -s -I {url} | grep -i 'content-type'"
        curl_process = await asyncio.create_subprocess_shell(
            curl_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        curl_stdout, curl_stderr = await curl_process.communicate()
        
        # Read results
        try:
            with open(output_file, 'r') as f:
                results = f.read()
        except FileNotFoundError:
            results = "No results file generated"
        
        content_type = curl_stdout.decode().strip() if curl_stdout else "Unknown"
        
        return [types.TextContent(type="text", text=
            f"📝 Form analysis completed!\n\n"
            f"🎯 Target: {url}\n"
            f"🔍 Scan Type: {scan_type}\n"
            f"📋 Content-Type: {content_type}\n"
            f"📁 Results saved to: {output_file}\n"
            f"🕒 Completed: {datetime.datetime.now().isoformat()}\n\n"
            f"📝 Results Preview:\n{results[:500]}{'...' if len(results) > 500 else ''}"
        )]
    except asyncio.TimeoutError:
        return [types.TextContent(type="text", text="❌ Form analysis timed out after 3 minutes")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error during form analysis: {str(e)}")]


async def header_analysis(url: str, include_security: bool = True) -> Sequence[types.TextContent]:
    """
    Analyze HTTP headers for security information and misconfigurations.
    
    Args:
        url: Target URL to analyze
        include_security: Include security header analysis
        
    Returns:
        List containing TextContent with header analysis results
    """
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"header_analysis_{safe_url}_{timestamp}.txt"
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    try:
        # Basic header analysis
        header_cmd = f"curl -s -I {url}"
        
        process = await asyncio.create_subprocess_shell(
            header_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60.0)
        
        headers_output = stdout.decode() if stdout else ""
        
        # Security header analysis
        security_analysis = ""
        if include_security:
            security_headers = [
                "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
                "Strict-Transport-Security", "Content-Security-Policy", "Referrer-Policy"
            ]
            
            security_analysis = "\n\n🔒 Security Header Analysis:\n"
            for header in security_headers:
                if header.lower() in headers_output.lower():
                    security_analysis += f"✅ {header}: Present\n"
                else:
                    security_analysis += f"❌ {header}: Missing\n"
        
        # Save results
        full_analysis = f"""# HTTP Header Analysis

**Target:** {url}
**Analyzed:** {datetime.datetime.now().isoformat()}
**Output File:** {output_file}

## Raw Headers
{headers_output}

{security_analysis}

## Analysis Summary
- Response headers analyzed for security misconfigurations
- Security headers checked for presence
"""
        
        with open(output_file, 'w') as f:
            f.write(full_analysis)
        
        return [types.TextContent(type="text", text=
            f"📋 Header analysis completed!\n\n"
            f"🎯 Target: {url}\n"
            f"🔒 Security Analysis: {'Enabled' if include_security else 'Disabled'}\n"
            f"📁 Results saved to: {output_file}\n"
            f"🕒 Completed: {datetime.datetime.now().isoformat()}\n\n"
            f"📝 Headers Preview:\n{headers_output[:300]}{'...' if len(headers_output) > 300 else ''}"
        )]
    except asyncio.TimeoutError:
        return [types.TextContent(type="text", text="❌ Header analysis timed out after 1 minute")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error during header analysis: {str(e)}")]


async def ssl_analysis(url: str, port: int = 443) -> Sequence[types.TextContent]:
    """
    Perform SSL/TLS security assessment.
    
    Args:
        url: Target URL to analyze
        port: SSL port (default: 443)
        
    Returns:
        List containing TextContent with SSL analysis results
    """
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"ssl_analysis_{safe_url}_{timestamp}.txt"
    
    # Extract domain from URL
    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
    
    try:
        # Use testssl.sh for comprehensive SSL analysis
        ssl_cmd = f"testssl.sh --quiet --color 0 {domain}:{port} > {output_file} 2>&1"
        
        process = await asyncio.create_subprocess_shell(
            ssl_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300.0)
        
        # Read results
        try:
            with open(output_file, 'r') as f:
                results = f.read()
        except FileNotFoundError:
            results = "No results file generated"
        
        # Extract key findings
        key_findings = []
        if "Vulnerable" in results:
            key_findings.append("🚨 Vulnerable SSL/TLS configuration detected")
        if "TLS 1.0" in results or "TLS 1.1" in results:
            key_findings.append("⚠️ Outdated TLS versions detected")
        if "weak" in results.lower():
            key_findings.append("⚠️ Weak cipher suites detected")
        
        findings_summary = "\n".join(key_findings) if key_findings else "✅ No major issues detected"
        
        return [types.TextContent(type="text", text=
            f"🔐 SSL analysis completed!\n\n"
            f"🎯 Target: {domain}:{port}\n"
            f"📁 Results saved to: {output_file}\n"
            f"🕒 Completed: {datetime.datetime.now().isoformat()}\n\n"
            f"🔍 Key Findings:\n{findings_summary}\n\n"
            f"📝 Results Preview:\n{results[:500]}{'...' if len(results) > 500 else ''}"
        )]
    except asyncio.TimeoutError:
        return [types.TextContent(type="text", text="❌ SSL analysis timed out after 5 minutes")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error during SSL analysis: {str(e)}")]


async def subdomain_enum(url: str, enum_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """
    Perform subdomain enumeration using multiple tools.
    
    Args:
        url: Target domain to enumerate
        enum_type: Type of enumeration (basic, comprehensive, aggressive)
        
    Returns:
        List containing TextContent with subdomain enumeration results
    """
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"subdomain_enum_{safe_url}_{timestamp}.txt"
    
    # Extract domain from URL
    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
    
    try:
        enum_commands = []
        
        if enum_type == "basic":
            enum_commands = [
                f"subfinder -d {domain} -o {output_file}_subfinder",
                f"amass enum -d {domain} -o {output_file}_amass"
            ]
        elif enum_type == "comprehensive":
            enum_commands = [
                f"subfinder -d {domain} -o {output_file}_subfinder",
                f"amass enum -d {domain} -o {output_file}_amass",
                f"waybackurls {domain} | grep -o '[^/]*\\.{domain}' | sort -u > {output_file}_wayback"
            ]
        else:  # aggressive
            enum_commands = [
                f"subfinder -d {domain} -o {output_file}_subfinder",
                f"amass enum -d {domain} -o {output_file}_amass",
                f"waybackurls {domain} | grep -o '[^/]*\\.{domain}' | sort -u > {output_file}_wayback",
                f"gospider -s https://{domain} -d 1 -c 5 -o {output_file}_gospider"
            ]
        
        # Execute commands
        for cmd in enum_commands:
            await asyncio.create_subprocess_shell(
                f"{cmd} >> {output_file} 2>&1 &",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        
        # Wait for completion
        await asyncio.sleep(30)
        
        # Combine results
        combined_results = ""
        try:
            with open(output_file, 'r') as f:
                combined_results = f.read()
        except FileNotFoundError:
            combined_results = "No results file generated"
        
        # Count unique subdomains
        subdomain_count = len(set([line.strip() for line in combined_results.split('\n') if domain in line and line.strip()]))
        
        return [types.TextContent(type="text", text=
            f"🔍 Subdomain enumeration completed!\n\n"
            f"🎯 Target: {domain}\n"
            f"🔍 Enum Type: {enum_type}\n"
            f"📊 Subdomains Found: {subdomain_count}\n"
            f"📁 Results saved to: {output_file}\n"
            f"🕒 Completed: {datetime.datetime.now().isoformat()}\n\n"
            f"📝 Results Preview:\n{combined_results[:500]}{'...' if len(combined_results) > 500 else ''}"
        )]
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error during subdomain enumeration: {str(e)}")]


async def web_audit(url: str, audit_type: str = "comprehensive") -> Sequence[types.TextContent]:
    """
    Perform comprehensive web application security audit.
    
    Args:
        url: Target URL to audit
        audit_type: Type of audit (basic, comprehensive, aggressive)
        
    Returns:
        List containing TextContent with audit results
    """
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace('://', '_').replace('/', '_').replace('.', '_')
    output_file = f"web_audit_{safe_url}_{timestamp}.txt"
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    try:
        audit_commands = []
        
        if audit_type == "basic":
            audit_commands = [
                f"nikto -h {url} -Format txt -o {output_file}_nikto",
                f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -o {output_file}_dirs"
            ]
        elif audit_type == "comprehensive":
            audit_commands = [
                f"nikto -h {url} -Format txt -o {output_file}_nikto",
                f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -o {output_file}_dirs",
                f"gobuster vhost -u {url} -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o {output_file}_vhosts",
                f"sqlmap --url {url} --batch --random-agent --level 1 --output-dir {output_file}_sqlmap",
                f"curl -I {url} | grep -i 'server\\|x-powered-by\\|x-'"
            ]
        else:  # aggressive
            audit_commands = [
                f"nikto -h {url} -Format txt -o {output_file}_nikto",
                f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -o {output_file}_dirs",
                f"gobuster vhost -u {url} -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o {output_file}_vhosts",
                f"sqlmap --url {url} --batch --random-agent --level 2 --output-dir {output_file}_sqlmap",
                f"dirb {url} /usr/share/wordlists/dirb/common.txt -o {output_file}_dirb",
                f"curl -I {url} | grep -i 'server\\|x-powered-by\\|x-'",
                f"testssl.sh --quiet --color 0 {url.replace('http://', '').replace('https://', '').split('/')[0]} > {output_file}_ssl"
            ]
        
        # Execute commands
        for cmd in audit_commands:
            await asyncio.create_subprocess_shell(
                f"{cmd} >> {output_file} 2>&1 &",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        
        # Wait for completion
        await asyncio.sleep(60)
        
        # Read results
        try:
            with open(output_file, 'r') as f:
                results = f.read()
        except FileNotFoundError:
            results = "No results file generated"
        
        # Generate summary
        summary = f"""# Web Application Security Audit

**Target:** {url}
**Audit Type:** {audit_type}
**Completed:** {datetime.datetime.now().isoformat()}
**Output File:** {output_file}

## Tools Used
- Nikto (web vulnerability scanner)
- Gobuster (directory/vhost enumeration)
- SQLMap (SQL injection testing)
- Dirb (directory enumeration)
- TestSSL.sh (SSL/TLS analysis)
- Curl (header analysis)

## Results
{results}
"""
        
        with open(output_file, 'w') as f:
            f.write(summary)
        
        return [types.TextContent(type="text", text=
            f"🔍 Web audit completed!\n\n"
            f"🎯 Target: {url}\n"
            f"🔍 Audit Type: {audit_type}\n"
            f"📁 Results saved to: {output_file}\n"
            f"🕒 Completed: {datetime.datetime.now().isoformat()}\n\n"
            f"📝 Results Preview:\n{results[:500]}{'...' if len(results) > 500 else ''}"
        )]
    except Exception as e:
        return [types.TextContent(type="text", text=f"❌ Error during web audit: {str(e)}")]

OUTPUT_FILE_PATTERNS = [
    # Core tool outputs
    "command_output.txt",
    "*.txt",
    "*.log",
    "*.out",
    "*.err",
    
    # Security analysis outputs
    "vuln_scan_*.txt",
    "web_enum_*.txt", 
    "network_discovery_*.txt",
    "exploit_search_*.txt",
    
    # File management outputs
    "*_output_*.txt",
    "report_*.markdown",
    "report_*.txt",
    "report_*.json",
    "file_analysis_*.txt",
    "downloads/*",
    
    # Session management outputs
    "sessions/*",
    "sessions/*/metadata.json",
    "sessions/active_session.txt",
    
    # Enhanced web application testing outputs
    "spider_*.txt",
    "form_analysis_*.txt",
    "header_analysis_*.txt",
    "ssl_analysis_*.txt",
    "subdomain_enum_*.txt",
    "web_audit_*.txt",
    "*_nikto",
    "*_dirs",
    "*_vhosts",
    "*_sqlmap",
    "*_dirb",
    "*_ssl",
    "*_subfinder",
    "*_amass",
    "*_wayback",
    "*_gospider"
]