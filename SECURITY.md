# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Batin, please report it responsibly.

### How to Report

1. **Do NOT open a public issue** for security vulnerabilities
2. Email security concerns to: `security@batin.dev` (or use GitHub's private vulnerability reporting)
3. Include the following in your report:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 60 days

### Scope

The following are in scope for security reports:

- Memory safety issues (though we use zero `unsafe` code)
- Denial of Service (DoS) via malformed input
- Information disclosure
- Authentication/authorization bypasses (if applicable)
- Dependency vulnerabilities

### Out of Scope

- Issues in dependencies (report to upstream maintainers)
- Social engineering attacks
- Physical security

### Safe Harbor

We consider security research conducted in accordance with this policy to be:

- Authorized and lawful
- Helpful to the community
- Not subject to legal action from us

Thank you for helping keep Batin secure!

## Security Best Practices

When using Batin in production:

1. **Sandbox untrusted files** - Process suspicious files in isolated environments
2. **Limit file sizes** - Use `max_read_bytes` configuration to prevent memory exhaustion
3. **Set timeouts** - Configure `timeout_ms` to prevent hanging on malformed input
4. **Update regularly** - Keep Batin and dependencies up to date
5. **Validate inputs** - Don't trust file extensions; always verify content

## Dependency Security

We regularly audit our dependencies using:

```bash
cargo audit
```

All dependencies are pinned to specific versions to ensure reproducible builds.
