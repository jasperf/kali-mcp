# Nmap Usage Guide

This guide covers common Nmap usage patterns and troubleshooting for the Kali MCP Server.

## Table of Contents

- [Common Issues](#common-issues)
- [Recommended Scan Types](#recommended-scan-types)
- [Permission Limitations](#permission-limitations)
- [Examples](#examples)

## Common Issues

### "Operation not permitted" Error

**Problem:**
```
Couldn't open a raw socket. Error: Operation not permitted (1)
```

**Cause:**
Nmap requires root privileges for certain scan types (SYN scans, OS detection, etc.) that use raw sockets.

**Solution:**
Use TCP connect scans (`-sT`) which don't require root privileges:

```bash
# ❌ This will fail without root
nmap -F localhost

# ✅ Use TCP connect scan instead
nmap -sT -F localhost
```

### Sudo Not Allowed

**Problem:**
```
Command 'sudo nmap -F localhost' is not allowed for security reasons.
```

**Cause:**
The MCP server has security restrictions that prevent running commands with `sudo` for safety.

**Solution:**
Use non-privileged scan types (see [Recommended Scan Types](#recommended-scan-types) below).

## Permission Limitations

The Kali MCP Server runs as a non-root user (`kali-user`) for security. This means certain Nmap features are restricted:

### ❌ Requires Root (NOT Available)

- **SYN Scans** (`-sS`): Default scan type, requires raw sockets
- **OS Detection** (`-O`): Requires raw packet manipulation
- **Traceroute** (`--traceroute`): Requires raw ICMP packets
- **IP Protocol Scan** (`-sO`): Requires raw sockets
- **FIN/NULL/Xmas Scans** (`-sF`, `-sN`, `-sX`): Require raw sockets

### ✅ Works Without Root (Available)

- **TCP Connect Scan** (`-sT`): Full TCP handshake, works without privileges
- **Service Version Detection** (`-sV`): Application version detection
- **Script Scanning** (`-sC`, `--script`): Run Nmap scripts
- **UDP Scan** (`-sU`): Some UDP scans work without root
- **Port Specification** (`-p`): Specify custom ports
- **Timing Templates** (`-T0` to `-T5`): Control scan speed
- **Output Formats** (`-oN`, `-oX`, `-oG`): Save results in various formats

## Recommended Scan Types

### Basic Host Discovery

```bash
# Fast scan of common ports (TCP connect)
nmap -sT -F <target>

# Scan specific ports
nmap -sT -p 80,443,8080 <target>

# Scan a port range
nmap -sT -p 1-1000 <target>
```

### Service and Version Detection

```bash
# Detect service versions
nmap -sT -sV <target>

# Fast scan with service detection
nmap -sT -F -sV <target>

# Aggressive service detection
nmap -sT -sV --version-intensity 9 <target>
```

### Script Scanning

```bash
# Run default scripts
nmap -sT -sC <target>

# Run specific scripts
nmap -sT --script http-headers <target>

# Run multiple scripts
nmap -sT --script http-headers,http-title,ssl-cert <target>

# List available scripts
nmap --script-help all
```

### Comprehensive Scans

```bash
# Comprehensive scan (all safe techniques)
nmap -sT -sV -sC -p- <target>

# Fast comprehensive scan
nmap -sT -sV -sC -F <target>

# Aggressive scan (combines multiple techniques)
nmap -sT -A <target>
```

### Network Scanning

```bash
# Scan a subnet
nmap -sT -F 192.168.1.0/24

# Scan multiple hosts
nmap -sT -F 192.168.1.1,10,20

# Scan with host list
nmap -sT -F -iL targets.txt
```

## Examples

### Example 1: Quick Port Check on Localhost

```bash
# Request
nmap -sT -F localhost

# Output
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-08 01:10 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000098s latency).
Other addresses for localhost (not scanned): ::1
All 100 scanned ports on localhost (127.0.0.1) are in ignored states.
Not shown: 100 closed tcp ports (conn-refused)

Nmap done: 1 IP address (1 host up) scanned in 0.03 seconds
```

**Interpretation:**
- Host is up and responding
- All 100 common ports are closed
- No services are currently listening

### Example 2: Web Server Discovery

```bash
# Scan common web ports with service detection
nmap -sT -p 80,443,8080,8443 -sV example.com
```

### Example 3: Comprehensive Network Audit

```bash
# Full port scan with service detection and scripts
nmap -sT -p- -sV -sC --open example.com
```

### Example 4: Vulnerability Assessment

```bash
# Run vulnerability detection scripts
nmap -sT -sV --script vuln example.com
```

## Best Practices

### 1. Always Use `-sT` for TCP Scans

Since root is not available, always explicitly specify TCP connect scan:

```bash
# ✅ Correct
nmap -sT -F target.com

# ❌ Will fail (tries SYN scan by default)
nmap -F target.com
```

### 2. Combine Techniques for Better Results

```bash
# Good: Fast scan with version detection
nmap -sT -F -sV target.com

# Better: Add script scanning
nmap -sT -F -sV -sC target.com

# Best: Save output for later analysis
nmap -sT -F -sV -sC -oN scan_results.txt target.com
```

### 3. Use Timing Templates for Control

```bash
# Slow and stealthy (avoid detection)
nmap -sT -T2 target.com

# Normal speed (default)
nmap -sT -T3 target.com

# Fast scan (more aggressive)
nmap -sT -T4 target.com

# Very fast (very aggressive, may be detected)
nmap -sT -T5 target.com
```

### 4. Save Your Results

```bash
# Save in normal format
nmap -sT -F -oN results.txt target.com

# Save in XML format (for parsing)
nmap -sT -F -oX results.xml target.com

# Save in all formats
nmap -sT -F -oA scan_results target.com
```

## Troubleshooting

### Scan is Too Slow

```bash
# Use faster timing template
nmap -sT -T4 target.com

# Scan fewer ports
nmap -sT --top-ports 100 target.com

# Reduce host timeout
nmap -sT --host-timeout 5m target.com
```

### No Results Returned

```bash
# Increase verbosity to see what's happening
nmap -sT -v target.com

# Even more verbose
nmap -sT -vv target.com

# Debug mode (very detailed)
nmap -sT -d target.com
```

### Target Seems Down

```bash
# Skip host discovery (assume host is up)
nmap -sT -Pn target.com

# Try different ports
nmap -sT -p- target.com
```

## Advanced Usage

### Using with MCP Session Management

```bash
# Create a session for your scan
session_create session_name="port_scan" target="example.com"

# Run the scan
nmap -sT -p- -sV -sC -oN scan.txt example.com

# Save the results
save_output content="$(cat scan.txt)" category="scan"

# Create a report
create_report title="Port Scan Results" findings="$(cat scan.txt)" report_type="markdown"
```

### Combining with Other Tools

```bash
# 1. Discover open ports with nmap
nmap -sT -F -oG - target.com | grep "/open/" > open_ports.txt

# 2. Run nikto on discovered web servers
nikto -h http://target.com

# 3. Enumerate directories
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
```

## References

- [Nmap Official Documentation](https://nmap.org/book/man.html)
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)
- [Port Scanning Basics](https://nmap.org/book/port-scanning.html)
- [TCP Connect Scan Documentation](https://nmap.org/book/scan-methods-connect-scan.html)

## Legal Notice

⚠️ **Important**: Only scan systems you own or have explicit permission to test. Unauthorized port scanning may be illegal in your jurisdiction.
