# Kali MCP Server Documentation

## Table of Contents

1. [Quick Start](#quick-start)
2. [Integration with Claude Desktop](#integration-with-claude-desktop)
3. [Project Overview](#project-overview)
4. [Development Guide](#development-guide)
5. [Testing](#testing)
6. [Security Considerations](#security-considerations)
7. [Changelog](#changelog)

## Quick Start

### Building and Running

```bash
# Build the Docker image
docker build -t kali-mcp-server .

# Run with default settings (SSE mode on port 8000)
docker run -p 8000:8000 kali-mcp-server

# Or use the convenience script
./run_docker.sh
```

## Integration with Claude Desktop

1. **Build and start the Docker container:**

   ```bash
   ./run_docker.sh
   ```

2. **Configure Claude Desktop**

   Edit your Claude Desktop config file at:
   `~/Library/Application Support/Claude/claude_desktop_config.json`

   Add this configuration:
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

3. **Restart Claude Desktop**

4. **Test the connection**

   In Claude Desktop, try these commands:
   ```
   /run uname -a
   /fetch https://example.com
   /resources
   ```

### Available Tools

- `/run <command>` - Execute a shell command
- `/fetch <url>` - Fetch content from a website
- `/resources` - List available system resources and commands

### Troubleshooting

- Ensure port 8000 is available and not used by another application
- Check that the Docker container is running with `docker ps`
- If you get connection errors, try restarting the container with `./run_docker.sh`
- For security reasons, not all commands are allowed

## Project Overview

This is a production-ready MCP (Model Context Protocol) server running in a Kali Linux Docker container. It provides AI assistants with access to a comprehensive security toolset for penetration testing and security analysis. The server communicates via Server-Sent Events (SSE) and allows AI to execute commands in a controlled environment.

### Architecture

The project is structured as a Python MCP server with three main components:

1. `kali_mcp_server/server.py` - Core server implementation that handles MCP protocol
2. `kali_mcp_server/tools.py` - Implementation of the tools offered by the server
3. Main entry points: `main.py` and `kali_mcp_server/__main__.py`

The server provides three main tools through the MCP protocol:

1. `run` - Execute shell commands in the Kali Linux environment
2. `fetch` - Fetch web content from specified URLs
3. `resources` - List available system resources and command examples

Commands are validated against an allowlist for security, and long-running commands are executed in the background.

## Development Guide

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

### Development Commands

```bash
# Install development dependencies
pip install -e ".[dev]"

# Type checking
pyright

# Linting
ruff check .

# Formatting
ruff format .

# Running tests
pytest
```

### Package Management

```bash
# Install dependencies
pip install -r requirements.txt

# Add a new dependency
pip install <package-name>
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=kali_mcp_server

# Or use the convenience script
./run_tests.sh
```

## Security Considerations

This container provides access to powerful security tools. It includes several security measures:

1. Commands are validated against an allowlist
2. The server runs as a non-root user inside the container
3. Long-running commands are executed with appropriate controls
4. Input validation is applied to commands and URLs

It should only be used responsibly and in controlled environments.

## Changelog

### Version 0.1.0

#### Production-Ready Improvements

- Renamed package from `mcp_simple_tool` to `kali_mcp_server` for clarity
- Separated code into logical modules
- Added comprehensive docstrings to all modules and functions
- Improved error handling with specific exceptions
- Added proper type hints throughout the codebase
- Added command validation against an allowlist
- Added URL validation in the fetch tool
- Updated Dockerfile to run as non-root user
- Improved error messages for security violations
- Made function and variable names more descriptive
- Standardized naming conventions throughout the codebase
- Added .dockerignore file for optimized Docker builds
- Improved Dockerfile with better caching and security practices
- Added run_docker.sh and run_tests.sh scripts for easier usage
- Added basic unit tests for core functionality