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
from typing import Sequence, Union

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
    
    # File operations
    ("ls", False),
    # Only allow cat on safe files
    ("cat /proc/", False),
    ("cat /var/log/", False),
    ("cat command_output.txt", False),
    ("cat *.txt", False),
    ("cat *.log", False),
    ("head", False),
    ("tail", False),
    ("find", True),  # Can be long-running
    ("grep", False),
    ("wc", False),
    
    # Utility commands
    ("echo", False),
    ("which", False),
    ("man", False),
    ("help", False),
]

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
                "sqlmap --url http://example.com --dbs": "SQL injection testing"
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