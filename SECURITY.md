# Security Policy

## Supported Versions

Advocate is currently in maintenance mode. Security updates are provided on a best-effort basis.

| Version | Supported | Notes |
|---------|-----------|-------|
| 1.x     | Yes    | Current stable release |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Advocate, please follow these steps:

### 1. Private Disclosure

Send an email to the maintainer with details about the vulnerability:

- **Email:** advocate@saynotolinux.com
- **Subject:** [SECURITY] Advocate Vulnerability Report

Include the following information:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if available)

### 2. Response Timeline

You can expect:
- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 72 hours
- **Fix or Mitigation:** As soon as possible, depending on severity

### 3. Public Disclosure

Vulnerabilities will be publicly disclosed after:
- A fix is available, OR
- 30 days have passed since private disclosure (whichever comes first)

## Security Scope

This policy covers vulnerabilities in:
- Advocate's core validation logic
- Address validation bypasses
- SSRF (Server-Side Request Forgery) vulnerabilities
- DNS rebinding bypasses
- Any other security issues in the Advocate library

## Security Features

Advocate provides the following security protections:

### Address Validation
- Blacklists and whitelists for IPs, ports, and hostnames
- Auto-detection of local addresses
- Validation of private, loopback, and reserved addresses

### SSRF Prevention
- Validates all connection attempts
- Prevents DNS rebinding attacks
- Handles redirects safely

### IPv6 Support
- Configurable IPv6 validation
- Support for various tunneling protocols (6to4, Teredo, DNS64)

## Known Limitations

### IPv6 Support

IPv6 support is still considered experimental. The following limitations exist:
- IPv6 addresses are ignored by default
- Enable with `AddrValidator(allow_ipv6=True)`
- Some IPv6 tunneling mechanisms may not be fully protected

### Proxy Support

Advocate **does not support** HTTP proxies. This is intentional to prevent proxy-based bypasses of security validations.

### Performance

Address validation adds overhead to each connection. For high-performance applications, consider:
- Caching validation results
- Using a pre-configured validator
- Running Advocate in a separate process

## Security Best Practices

When using Advocate:

### 1. Configure Properly
```python
import advocate

# Create a validator with appropriate settings
validator = advocate.AddrValidator(
    ip_blacklist={
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("172.16.0.0/12"),
    },
    hostname_blacklist={"*.internal", "*.local"},
)

# Use it with a session
session = advocate.Session(validator=validator)
```

### 2. Keep Dependencies Updated
- Regularly update `requests` and `urllib3`
- Monitor for security advisories

### 3. Network-Level Protection
- Consider using a proxy server for additional protection
- Use network segmentation to limit access
- Configure firewall rules appropriately

### 4. Monitoring
- Monitor for blocked requests
- Log validation failures
- Alert on suspicious activity

### 5. Custom Validators
For complex requirements, create custom validators:
```python
import advocate
import ipaddress

class MyValidator(advocate.AddrValidator):
    def is_ip_allowed(self, addr_ip, _local_addresses=None):
        # Custom logic here
        if addr_ip in ipaddress.ip_network("192.0.2.0/24"):
            return False
        return super().is_ip_allowed(addr_ip, _local_addresses)
```

## Security Checklist for Contributors

When contributing to Advocate, consider:

- [ ] Have you tested with various address formats?
- [ ] Have you tested with IPv4, IPv6, and tunneling protocols?
- [ ] Have you tested with different DNS configurations?
- [ ] Have you tested with redirects?
- [ ] Have you tested edge cases and boundary conditions?
- [ ] Does your change maintain backward compatibility?
- [ ] Does your change introduce any new security risks?

## Credits

Security researchers who have responsibly disclosed vulnerabilities will be credited in the release notes and changelog.
