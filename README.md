# 🛡️ Kali MCP Server

A production-ready MCP (Model Context Protocol) server running in a Kali Linux Docker container, providing AI assistants with access to a comprehensive security toolset.

[![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)](https://www.kali.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

## 📋 Overview

This project provides a Docker containerized MCP server that runs on Kali Linux, giving AI assistants (like Claude) access to a full suite of security and penetration testing tools. The server supports both stdio transport (for Claude Desktop integration) and SSE transport (for standalone/VPS deployment), allowing AI to execute commands in a controlled environment with appropriate security measures.

## ✨ Features

- **🔒 Security Tools Access**: Full access to Kali Linux security toolset through a controlled interface
- **🛡️ Command Validation**: Commands are validated against an allowlist for security
- **🌐 Web Content Fetching**: Retrieve and analyze web content
- **📊 Resource Information**: Comprehensive system resource details and command examples
- **⚡ Root Privileges**: Container runs as root to enable privileged network operations (SYN scans, OS detection, etc.)

### 🔧 Pre-installed Security Tools

- **🔍 Network Scanning**: nmap, netcat
- **🕸️ Web Application Testing**: nikto, gobuster, dirb
- **🧪 Penetration Testing**: metasploit-framework
- **🔑 Credential Testing**: hydra
- **💉 Data Extraction**: sqlmap
- **ℹ️ Information Gathering**: whois, dig, host

## 🚀 Quick Start

### 🐳 Building and Running the Container

```bash
# Quick start with the helper script
./run_docker.sh

# Or manually:
# Build the Docker image
docker build -t kali-mcp-server .

# Run with default settings (SSE mode on port 8000)
docker run -p 8000:8000 kali-mcp-server
```

### 🔌 Connecting to Claude Desktop

1. Build the Docker image first:
   ```bash
   docker build -t kali-mcp-server .
   ```

2. Edit your Claude Desktop config file:
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   - **Linux**: `~/.config/Claude/claude_desktop_config.json`

3. Add this configuration:
   ```json
   {
     "mcpServers": {
       "kali-mcp-server": {
         "command": "docker",
         "args": ["run", "-i", "kali-mcp-server", "python", "-m", "kali_mcp_server", "--transport", "stdio"]
       }
     }
   }
   ```

4. **Completely quit and restart Claude Desktop** (Cmd+Q on macOS, not just close the window)

5. Check the MCP server status in Claude Desktop settings:
   - Open Claude Desktop
   - Go to Settings → Developer → Local MCP servers
   - You should see `kali-mcp-server` listed

6. Test the connection by asking Claude to use the tools:
   ```
   Can you run a quick nmap scan on localhost using the run tool?
   ```

## 🛠️ Available MCP Tools

The server provides several tools through the MCP protocol. In Claude Desktop, these tools are invoked automatically by the AI - you simply ask Claude in natural language, and it will use the appropriate tool.

### 💻 `run` - Execute Commands

Run security tools and commands in the Kali Linux environment.

**Example request to Claude:**
```
Can you run nmap -F localhost?
```

Claude will automatically use the `run` tool with the command `nmap -F localhost`.

Commands are validated against an allowlist for security. Long-running commands will be executed in the background with results saved to an output file.

### 🌐 `fetch` - Retrieve Web Content

Fetch and analyze web content from specified URLs.

**Example request to Claude:**
```
Can you fetch https://example.com?
```

### 📈 `resources` - List Available Resources

Get information about the system and available commands. The AI automatically uses these resources to understand available commands.

**Example request to Claude:**
```
What security tools are available?
```

### 🚀 `vulnerability_scan` - Automated Vulnerability Assessment

Perform automated vulnerability assessment with multiple tools.

**Example requests to Claude:**
```
Can you run a quick vulnerability scan on 127.0.0.1?
Run a comprehensive vulnerability scan on example.com
```

**Scan Types:**
- `quick`: Fast scan with nmap and nikto
- `comprehensive`: Full scan with multiple tools
- `web`: Web-focused vulnerability assessment
- `network`: Network-focused vulnerability assessment

### 🌐 `web_enumeration` - Web Application Discovery

Perform comprehensive web application discovery and enumeration.

**Example requests to Claude:**
```
Perform full web enumeration on http://example.com
Run aggressive web enumeration on example.com
```

**Enumeration Types:**
- `basic`: Basic web enumeration with nikto and gobuster
- `full`: Comprehensive enumeration including vhost discovery
- `aggressive`: Aggressive enumeration with SQL injection testing

### 🔍 `network_discovery` - Network Reconnaissance

Perform multi-stage network reconnaissance and discovery.

**Example requests to Claude:**
```
Do comprehensive network discovery on 192.168.1.0/24
Run stealth network discovery on example.com
```

**Discovery Types:**
- `quick`: Quick network discovery
- `comprehensive`: Comprehensive network mapping
- `stealth`: Stealthy network reconnaissance

### 🔍 `exploit_search` - Exploit Database Search

Search for exploits using searchsploit and other exploit databases.

**Example requests to Claude:**
```
Search for Apache web exploits
Find exploits for CVE-2021-44228
```

**Search Types:**
- `all`: Search all exploit types
- `web`: Web application exploits
- `remote`: Remote exploits
- `local`: Local exploits
- `dos`: Denial of service exploits

### 💾 `save_output` - Save Content to File

Save content to a timestamped file for evidence collection.

**Example requests to Claude:**
```
Save these scan results to a file called my_scan
Save this enumeration data as evidence
```

**Categories:**
- `general`: General content (default)
- `scan`: Vulnerability scan results
- `enum`: Enumeration results
- `evidence`: Evidence collection

### 📋 `create_report` - Generate Structured Reports

Generate a structured report from findings.

**Example requests to Claude:**
```
Create a markdown report titled "Security Assessment Report" with these findings
Generate a JSON report for the network scan results
```

**Report Types:**
- `markdown`: Markdown format (default)
- `text`: Plain text format
- `json`: JSON format

### 🔍 `file_analysis` - Analyze Files

Analyze a file using various tools (file type, strings, hash).

**Example requests to Claude:**
```
Analyze the file at ./suspicious_file
Can you analyze /path/to/downloaded/file?
```

**Analysis includes:**
- File type detection
- String extraction
- SHA256 hash
- File metadata
- Content preview

### 📥 `download_file` - Download Files

Download a file from a URL and save it locally.

**Example requests to Claude:**
```
Download https://example.com/file.txt and save it as downloaded_file
Download https://example.com/script.sh
```

**Features:**
- Automatic filename extraction from URL
- SHA256 hash generation
- Content-type detection
- Safe filename sanitization

### 🗂️ `session_create` - Create New Session

Create a new pentest session with name, description, and target.

**Example requests to Claude:**
```
Create a session called "web_app_test" for security assessment of example.com
Start a new session for scanning 192.168.1.0/24
```

**Features:**
- Session metadata storage
- Automatic session activation
- Organized file structure

### 📋 `session_list` - List Sessions

List all pentest sessions with metadata and status.

**Example request to Claude:**
```
Show me all sessions
```

**Shows:**
- All available sessions
- Active session indicator
- Session descriptions and targets
- Creation dates and history counts

### 🔄 `session_switch` - Switch Sessions

Switch to a different pentest session.

**Example request to Claude:**
```
Switch to the web_app_test session
```

**Features:**
- Validates session existence
- Updates active session
- Shows session details after switch

### 📊 `session_status` - Session Status

Show current session status and summary.

**Example request to Claude:**
```
What's the current session status?
```

**Shows:**
- Active session details
- Session metadata
- File count and history
- Recent activity

### 🗑️ `session_delete` - Delete Session

Delete a pentest session and all its evidence.

**Example request to Claude:**
```
Delete the old_session
```

**Safety Features:**
- Cannot delete active session
- Confirms deletion with session details
- Removes all session files and evidence

### 📜 `session_history` - Session History

Show command/evidence history for the current session.

**Example request to Claude:**
```
Show me the session history
```

**Shows:**
- Chronological history of activities
- Action types and timestamps
- Session-specific evidence tracking

## Enhanced Web Application Testing Tools

### 🕷️ Spider Website
Comprehensive web crawling and spidering using gospider.

**Example request to Claude:**
```
Spider https://example.com with depth 2 and 10 threads
```

**Parameters:**
- `url` (required): Target URL to spider
- `depth` (optional): Crawling depth (default: 2)
- `threads` (optional): Number of concurrent threads (default: 10)

### 📝 Form Analysis
Discover and analyze web forms for security testing.

**Example request to Claude:**
```
Do a comprehensive form analysis on https://example.com
```

**Parameters:**
- `url` (required): Target URL to analyze
- `scan_type` (optional): Type of analysis - "basic", "comprehensive", "aggressive" (default: "comprehensive")

### 📋 Header Analysis
Analyze HTTP headers for security information and misconfigurations.

**Example request to Claude:**
```
Analyze the headers of https://example.com including security headers
```

**Parameters:**
- `url` (required): Target URL to analyze
- `include_security` (optional): Include security header analysis (default: true)

### 🔐 SSL Analysis
Perform SSL/TLS security assessment using testssl.sh.

**Example request to Claude:**
```
Run SSL analysis on example.com
```

**Parameters:**
- `url` (required): Target URL to analyze
- `port` (optional): SSL port (default: 443)

### 🔍 Subdomain Enumeration
Perform subdomain enumeration using multiple tools (subfinder, amass, waybackurls).

**Example request to Claude:**
```
Do comprehensive subdomain enumeration on example.com
```

**Parameters:**
- `url` (required): Target domain to enumerate
- `enum_type` (optional): Type of enumeration - "basic", "comprehensive", "aggressive" (default: "comprehensive")

### 🔍 Web Audit
Perform comprehensive web application security audit.

**Example request to Claude:**
```
Run a comprehensive web audit on https://example.com
```

**Parameters:**
- `url` (required): Target URL to audit
- `audit_type` (optional): Type of audit - "basic", "comprehensive", "aggressive" (default: "comprehensive")

**Tools Used in Web Audit:**
- Nikto (web vulnerability scanner)
- Gobuster (directory/vhost enumeration)
- SQLMap (SQL injection testing)
- Dirb (directory enumeration)
- TestSSL.sh (SSL/TLS analysis)
- Curl (header analysis)

## Session Management Tools

## ⚠️ Troubleshooting

### 🔌 Connection Issues

**"Server disconnected" or "Failed to connect" errors:**
1. Ensure Docker is running: `docker ps`
2. Rebuild the Docker image: `docker build -t kali-mcp-server .`
3. Check your config uses `stdio` transport (not SSE) as shown above
4. Completely quit and restart Claude Desktop (Cmd+Q on macOS)
5. Check Claude Desktop logs:
   - **macOS**: `~/Library/Logs/Claude/mcp*.log`
   - **Windows**: `%APPDATA%\Claude\logs\`
   - **Linux**: `~/.config/Claude/logs/`

**"Unexpected token" or JSON errors:**
- This usually means the config file has a syntax error
- Validate your JSON: `cat ~/Library/Application\ Support/Claude/claude_desktop_config.json | python3 -m json.tool`
- Ensure you're using the stdio transport configuration (not SSE)

### ⚙️ Command Execution Problems

- If commands timeout, try running them in the background: `command > output.txt &`
- Use `/resources` to see examples of properly formatted commands
- For permission errors, ensure you're not trying to access protected system areas

## 🔒 Security Considerations

This container provides access to powerful security tools and runs with root privileges. Please observe the following:

### ⚠️ Important Security Notes

- **Container runs as ROOT**: This enables privileged operations but reduces isolation
- **Use only in controlled environments**: Not recommended for shared or untrusted networks
- **Do not expose to the internet**: The container is designed for local use only
- Commands are validated against an allowlist for security
- Only use this tool for legitimate security testing with proper authorization

### 🛡️ Root Privileges Impact

**Capabilities Enabled:**
- Full Nmap scan capabilities (SYN scans with `-sS`, OS detection with `-O`, version detection with `-sV`)
- Raw socket access for packet crafting
- Low-level network operations
- All security tools function without "Operation not permitted" errors

**Security Risks:**
- Reduced container isolation compared to non-root execution
- Potential for container escape if vulnerabilities exist
- Greater impact if the container is compromised

**Recommendations:**
- Use only on isolated development machines or dedicated security testing VMs
- Consider using a VPS deployment with proper hardening (see `docs/VPS_DEPLOYMENT.md`)
- Avoid running on production systems or shared infrastructure
- Review the [VPS Deployment Guide](docs/VPS_DEPLOYMENT.md) for production use cases with additional security measures

## 📋 Requirements

- Docker (Docker Desktop or Docker Engine)
- Claude Desktop (supports MCP protocol)
- 2GB+ free disk space for the Kali Linux image

## 👨‍💻 Development

### 🛠️ Setting Up a Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/kali-mcp-server.git
cd kali-mcp-server

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -e ".[dev]"
```

### 🧪 Running Tests

```bash
# Run tests with the helper script
./run_tests.sh

# Or manually:
# Run all tests
pytest

# Run with coverage
pytest --cov=kali_mcp_server
```


## 🙏 Acknowledgements

- Kali Linux for their security-focused distribution
- Anthropic for Claude and the MCP protocol
- The open-source security tools community

---

<p align="center">
  <sub>Built for security professionals and AI assistants</sub>
</p>
