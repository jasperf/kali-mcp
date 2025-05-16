# Kali MCP Server

A production-ready MCP (Model Context Protocol) server running in a Kali Linux Docker container, providing AI assistants with access to a comprehensive security toolset.

## Overview

This project provides a Docker containerized MCP server that runs on Kali Linux, giving AI assistants (like Claude) access to a full suite of security and penetration testing tools. The server communicates via Server-Sent Events (SSE) and allows AI to execute commands in a controlled environment with appropriate security measures.

## Features

- **Security Tools Access**: Full access to Kali Linux security toolset through a controlled interface
- **Command Validation**: Commands are validated against an allowlist for security
- **Web Content Fetching**: Retrieve and analyze web content
- **Resource Information**: Comprehensive system resource details and command examples
- **Security Focus**: Running as non-root user with appropriate permissions

### Pre-installed Security Tools

- **Network Scanning**: nmap, netcat
- **Web Application Testing**: nikto, gobuster, dirb
- **Penetration Testing**: metasploit-framework
- **Credential Testing**: hydra
- **Data Extraction**: sqlmap
- **Information Gathering**: whois, dig, host

## Quick Start

### Building and Running the Container

```bash
# Quick start with the helper script
./run_docker.sh

# Or manually:
# Build the Docker image
docker build -t kali-mcp-server .

# Run with default settings (SSE mode on port 8000)
docker run -p 8000:8000 kali-mcp-server
```

### Connecting to Claude Desktop

1. Edit your Claude Desktop config file:
   - Location: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Add this configuration:
     ```json
     {
       "mcpServers": {
         "kali-mcp-server": {
           "transport": "sse",
           "url": "http://localhost:8000/sse",
           "command": "docker run -p 8000:8000 kali-mcp-server"
         }
       }
     }
     ```

2. Restart Claude Desktop
3. Test the connection with a simple command:
   ```
   /run nmap -F localhost
   ```

## Available MCP Tools

The server provides three main tools through the MCP protocol:

### 1. `run` - Execute Commands

Run security tools and commands in the Kali Linux environment.

```
/run nmap -F localhost
```

Commands are validated against an allowlist for security. Long-running commands will be executed in the background with results saved to an output file.

### 2. `fetch` - Retrieve Web Content

Fetch and analyze web content from specified URLs.

```
/fetch https://example.com
```

### 3. `resources` - List Available Resources

Get information about the system and available commands.

```
/resources
```

## Troubleshooting

### Connection Issues

- Ensure port 8000 is available on your machine
- Check that the Docker container is running: `docker ps`
- Verify the URL in Claude Desktop configuration matches the container's port

### Command Execution Problems

- If commands timeout, try running them in the background: `command > output.txt &`
- Use `/resources` to see examples of properly formatted commands
- For permission errors, ensure you're not trying to access protected system areas

## Security Considerations

This container provides access to powerful security tools. Please observe the following:

- Use responsibly and only in controlled environments
- The container is designed to be run locally and should not be exposed to the internet
- Commands are validated against an allowlist for security
- The server runs as a non-root user inside the container
- Only use this tool for legitimate security testing with proper authorization

## Requirements

- Docker
- Claude Desktop
- Port 8000 available on your host machine

## Development

### Setting Up a Development Environment

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

### Running Tests

```bash
# Run tests with the helper script
./run_tests.sh

# Or manually:
# Run all tests
pytest

# Run with coverage
pytest --cov=kali_mcp_server
```

### Code Quality

```bash
# Type checking
pyright

# Linting
ruff check .

# Formatting
ruff format .
```

## Documentation

For more detailed documentation, see:

- [DOCS.md](DOCS.md) - Complete project documentation
- [CLAUDE.md](CLAUDE.md) - Guidance for Claude Code