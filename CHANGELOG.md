# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.2]: https://github.com/yourusername/kali-mcp-server/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/yourusername/kali-mcp-server/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/yourusername/kali-mcp-server/releases/tag/v1.0.0
