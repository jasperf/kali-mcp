# Claude Code Integration Guide

This guide explains how to integrate the Kali MCP Server with Claude Code for AI-driven security testing directly in your development environment.

## Overview

Claude Code is Anthropic's official CLI tool that brings Claude's capabilities to your terminal and development workflow. By integrating the Kali MCP server, you can use natural language to execute security assessments, vulnerability scans, and penetration testing commands.

## Prerequisites

- Docker installed and running
- Claude Code installed ([Installation guide](https://docs.claude.com/en/docs/claude-code))
- Kali MCP Server Docker image built:
  ```bash
  docker build -t kali-mcp-server .
  ```

## Configuration Options

### Option 1: Using the CLI (Recommended)

Add the Kali MCP server using the Claude Code CLI:

```bash
claude mcp add --transport stdio kali-mcp-server docker -- run -i kali-mcp-server python -m kali_mcp_server --transport stdio
```

**Note:** The `--` separator tells the CLI to treat everything after `docker` as arguments, preventing `-i` from being interpreted as a flag.

**Verify the configuration:**
```bash
# List all configured MCP servers
claude mcp list

# Get details about the Kali MCP server
claude mcp get kali-mcp-server
```

### Option 2: Manual Configuration

Edit the managed MCP configuration file:

**macOS:**
```bash
sudo nano "/Library/Application Support/ClaudeCode/managed-mcp.json"
```

**Windows:**
```bash
notepad "C:\ProgramData\ClaudeCode\managed-mcp.json"
```

**Linux:**
```bash
sudo nano /etc/claude-code/managed-mcp.json
```

Add this configuration:
```json
{
  "mcpServers": {
    "kali-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "kali-mcp-server", "python", "-m", "kali_mcp_server", "--transport", "stdio"]
    }
  }
}
```

### Option 3: Project-Specific Setup

Create a `.mcp.json` file in your project root (this configuration will be shared with your team):

```bash
cat > .mcp.json << 'EOF'
{
  "mcpServers": {
    "kali-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "kali-mcp-server", "python", "-m", "kali_mcp_server", "--transport", "stdio"]
    }
  }
}
EOF
```

## Container Lifecycle

Understanding when and how the Docker container runs:

- **Automatic Start**: The container starts automatically when Claude Code first needs to use the MCP server
- **On-Demand Execution**: Container runs only when you interact with Claude Code and request security tools
- **Session Duration**: Container stays running during your Claude Code session
- **Automatic Cleanup**: Container stops and is removed when Claude Code session ends

**Monitor container lifecycle:**
```bash
# Watch for container creation/termination
watch -n 1 'docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Status}}"'
```

## Persistent Sessions (Optional)

By default, sessions and evidence are ephemeral. To persist data across container restarts, mount a volume:

**Update your configuration:**
```json
{
  "mcpServers": {
    "kali-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run",
        "-i",
        "-v",
        "${HOME}/kali-mcp-evidence:/evidence",
        "kali-mcp-server",
        "python",
        "-m",
        "kali_mcp_server",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

**Create the evidence directory:**
```bash
mkdir -p ~/kali-mcp-evidence
```

## Usage Examples

Once configured, use natural language in Claude Code to execute security tools:

### Network Scanning
```
Can you run a quick nmap scan on localhost?
```

### Vulnerability Assessment
```
Run a comprehensive vulnerability scan on example.com
```

### Web Enumeration
```
Perform full web enumeration on http://testsite.local
```

### Session Management
```
Create a new session called "webapp_test" for testing example.com
```

### Exploit Search
```
Search for Apache web exploits
```

## Verification

Test the integration by asking Claude Code:

```
What security tools are available in the Kali MCP server?
```

Claude should respond with information about the available tools and their capabilities.

## Troubleshooting

### Container Not Starting

**Check Docker is running:**
```bash
docker ps
```

**Verify image exists:**
```bash
docker images | grep kali-mcp-server
```

**Rebuild if necessary:**
```bash
docker build -t kali-mcp-server .
```

### MCP Server Not Found

**List configured servers:**
```bash
claude mcp list
```

**Check configuration file:**
```bash
# macOS
cat "/Library/Application Support/ClaudeCode/managed-mcp.json"

# Linux
cat /etc/claude-code/managed-mcp.json
```

### Permission Errors

If you encounter permission errors with the managed MCP config:

```bash
# macOS/Linux
sudo chmod 644 "/Library/Application Support/ClaudeCode/managed-mcp.json"
```

### Container Exits Immediately

**Check container logs:**
```bash
docker logs $(docker ps -a -q --filter ancestor=kali-mcp-server | head -1)
```

**Test container manually:**
```bash
docker run -i kali-mcp-server python -m kali_mcp_server --transport stdio
```

## Differences from Claude Desktop

| Feature | Claude Desktop | Claude Code |
|---------|---------------|-------------|
| Container Startup | When app launches | On-demand (first use) |
| Container Lifecycle | Runs while app is open | Runs during session |
| Configuration Location | `claude_desktop_config.json` | `managed-mcp.json` or `.mcp.json` |
| Scope | User-specific | User, project, or local |
| Persistence | Manual volume mount | Manual volume mount |

## Security Considerations

- **Review the server code** before adding any MCP server to your configuration
- **Use in controlled environments** - the Kali tools are powerful and should only be used for authorized testing
- **Container runs as root** to enable privileged operations (see main README for security implications)
- **Project-scope config** (`.mcp.json`) is shared with your team - ensure everyone understands the security implications

## Advanced Configuration

### Environment Variables

Pass environment variables to the container:

```json
{
  "mcpServers": {
    "kali-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "-e", "LOG_LEVEL=debug", "kali-mcp-server", "python", "-m", "kali_mcp_server", "--transport", "stdio"],
      "env": {
        "CUSTOM_VAR": "value"
      }
    }
  }
}
```

### Network Configuration

For network testing, you may need to use host networking:

```json
{
  "mcpServers": {
    "kali-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "--network", "host", "kali-mcp-server", "python", "-m", "kali_mcp_server", "--transport", "stdio"]
    }
  }
}
```

**Warning:** Host networking gives the container access to your host's network stack. Use with caution.

## Resources

- [Claude Code Documentation](https://docs.claude.com/en/docs/claude-code)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [Kali MCP Server GitHub](https://github.com/yourusername/kali-mcp-server)

## Next Steps

- Read the [main README](../README.md) for available tools and usage examples
- Check [VPS_DEPLOYMENT.md](VPS_DEPLOYMENT.md) for remote deployment options
- Review [NMAP.md](NMAP.md) for Nmap-specific guidance

---

**Note:** Claude Code is actively developed. Configuration formats and locations may change. Check the [official documentation](https://docs.claude.com/en/docs/claude-code/mcp) for the latest information.
