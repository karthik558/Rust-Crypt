# Security Policy

*Last updated: 2025-03-01 07:10:16 UTC*

## Security Disclaimer

This tool implements strong encryption using industry-standard algorithms (AES-256-GCM with Argon2 key derivation). However, please be aware of the following security considerations:

1. **No Warranty**: This software is provided "as is" without warranty of any kind. The author (karthik558) is not responsible for any data loss or security breaches resulting from the use of this tool.

2. **Password Security**: The strength of the encryption directly depends on your password quality. Use strong, unique passwords and store them securely.

3. **Key Management**: This tool does not manage keys for you. If you forget your password, there is NO WAY to recover your encrypted data.

4. **Memory Safety**: While Rust provides memory safety guarantees, this tool has not undergone formal security auditing.

5. **Implementation Risks**: Cryptographic implementations may contain undetected vulnerabilities or become obsolete as cryptography advances.

6. **No Backdoors**: This software intentionally contains no backdoors or key escrow mechanisms, meaning lost passwords result in permanently inaccessible data.

## Reporting a Vulnerability

If you discover a security vulnerability within this project, please send an email to [dev@karthiklal.in](mailto:dev@karthiklal.in). 

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

All security vulnerabilities will be promptly addressed.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.0   | :white_check_mark: |

By using this tool, you acknowledge these risks and agree to use it at your own responsibility. For highly sensitive information, consider using professional security solutions with proper key management and recovery mechanisms.