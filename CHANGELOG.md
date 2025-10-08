# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.6] - 2025-10-08

### Added
- **Claude Code integration guide** in `docs/CLAUDE_CODE.md`
  - Three configuration options: CLI (recommended), manual, and project-specific
  - Container lifecycle explanation (on-demand startup, automatic cleanup)
  - Persistent sessions setup with volume mounts
  - Usage examples with natural language requests
  - Comprehensive troubleshooting guide
  - Comparison table: Claude Desktop vs Claude Code
  - Advanced configuration (environment variables, network modes)
  - Security considerations for Claude Code integration

### Documentation
- Complete guide for integrating Kali MCP server with Claude Code CLI
- Instructions for managed MCP config and project-scope `.mcp.json`
- Container lifecycle management and monitoring
- Verification steps and common error solutions

## [1.0.5] - 2025-10-08

### Changed
- **Updated README.md documentation for clarity**
  - Clarified transport modes: stdio (Claude Desktop) vs. SSE (standalone/VPS)
  - Replaced confusing `/tool_name` syntax with natural language examples
  - Updated all tool usage examples to show actual user interaction patterns
  - Explained that MCP tools are automatically invoked by Claude, not typed by users

### Documentation
- Overview now mentions both stdio and SSE transport modes and their use cases
- All tool examples now show natural language requests instead of slash command notation
- Improved user experience by showing real-world Claude Desktop interaction patterns

## [1.0.4] - 2025-10-08

### Changed
- **Container now runs as root user** to enable privileged security operations
  - Allows full Nmap scan capabilities (SYN scans, OS detection, version detection)
  - Enables use of tools requiring raw socket access
  - Permits packet crafting and low-level network operations
  - Removes "Operation not permitted" errors for privileged operations

### Security
- **IMPORTANT**: Running as root reduces container isolation
- Container should only be used in controlled, trusted environments
- Not recommended for production deployments without additional hardening
- Consider using VPS deployment guide (docs/VPS_DEPLOYMENT.md) for production use cases
- Review security implications before deploying in shared environments

### Removed
- Non-root user (mcpuser) execution constraint
- User/group creation and permission management from Dockerfile

## [1.0.3] - 2025-10-08

### Added
- VPS deployment guide in `docs/VPS_DEPLOYMENT.md`
  - Complete guide for deploying with root privileges on Linux VPS
  - Three deployment options (privileged Docker, direct installation, Docker Compose)
  - Comprehensive security measures and hardening guide
  - SSH tunneling setup for secure remote access
  - Firewall configuration and access control
  - Systemd service configuration for auto-start
  - Claude Desktop remote connection options
  - Advanced Nmap usage with full root capabilities
  - Performance benchmarks (4x faster full port scans)
  - Cost optimization tips and VPS provider recommendations
  - Legal and ethical considerations for VPS scanning

### Documentation
- Detailed comparison: non-root vs. root Nmap capabilities
- Production deployment patterns with HTTPS reverse proxy
- Monitoring and logging setup
- Security best practices for exposed MCP servers

## [1.0.2] - 2025-10-08

### Added
- Comprehensive Nmap usage guide in `docs/NMAP.md`
  - Common permission issues and solutions ("Operation not permitted" error)
  - Permission limitations (what requires root vs. what works without)
  - Recommended scan types for non-root usage
  - Best practices for using `-sT` TCP connect scans
  - Real-world examples with expected output
  - Troubleshooting guide for common scan issues
  - Advanced usage with MCP session management
  - Integration patterns with other security tools

### Documentation
- Added detailed explanation of "Operation not permitted" error
- Documented why sudo is not allowed in the MCP server
- Provided workarounds for all restricted Nmap features
- Included timing templates and output format options

## [1.0.1] - 2025-10-08

### Changed
- **Updated Claude Desktop integration to use stdio transport** instead of SSE for better compatibility
- Simplified configuration - Claude Desktop now automatically starts the Docker container
- Updated README.md with correct integration instructions for stdio transport
- Removed port 8000 requirement from documentation (not needed with stdio)

### Added
- Comprehensive troubleshooting section in README.md
- Config file locations for macOS, Windows, and Linux
- Step-by-step verification instructions for Claude Desktop integration
- Common error solutions ("Server disconnected", "Unexpected token" JSON errors)

### Fixed
- Fixed "spawn docker run -p 8000:8000 kali-mcp-server ENOENT" error
- Fixed "Unexpected token 'C', 'Connect to'... is not valid JSON" error
- Corrected config format from single string to command/args array

## [1.0.0] - 2025-10-08

### Added
- Initial release of Kali MCP Server
- Docker containerized MCP server running on Kali Linux
- 20+ security tools pre-installed (nmap, nikto, metasploit, etc.)
- Core MCP tools: `run`, `fetch`, `resources`
- Advanced security tools:
  - `vulnerability_scan` - Automated vulnerability assessment
  - `web_enumeration` - Web application discovery
  - `network_discovery` - Network reconnaissance
  - `exploit_search` - Exploit database search
- Evidence collection tools:
  - `save_output` - Save content to timestamped files
  - `create_report` - Generate structured reports
  - `file_analysis` - Analyze files with multiple tools
  - `download_file` - Download and analyze remote files
- Session management:
  - `session_create`, `session_list`, `session_switch`
  - `session_status`, `session_delete`, `session_history`
- Web application testing tools:
  - `spider_website` - Web crawling and spidering
  - `form_analysis` - Web form vulnerability analysis
  - `header_analysis` - HTTP header security analysis
  - `ssl_analysis` - SSL/TLS security assessment
  - `subdomain_enum` - Subdomain enumeration
  - `web_audit` - Comprehensive web security audit
- Command validation with security allowlist
- Non-root user execution for improved security
- Background execution support for long-running commands
- SSE and stdio transport support
- Comprehensive test suite
- Docker helper scripts for easy deployment

### Security
- Commands validated against allowlist
- Server runs as non-root user (kali-user)
- Controlled environment execution
- Input validation for all tools
