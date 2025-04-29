# Security Scanner

A Python-based tool for passive security reconnaissance of company domains. It discovers subdomains and evaluates their security posture using only publicly available data.

## Purpose

This tool is designed for security enthusiasts, researchers, and professionals to passively assess the online presence and security configurations of target domains without active scanning or intrusion.

## Features

- **Subdomain Discovery**: Uses Certificate Transparency logs (crt.sh), DNS records (TXT, MX, NS), and common subdomain prefixes.
- **Security Analysis**: Checks security headers, SSL/TLS configurations, DNS records, cookies, and more.
- **Reporting**: Provides a summary with security scores, top issues, and strengths for each target.

## Usage

Run the tool with targets specified as CompanyName:URL pairs.

### Commands

- **Scan a Single Target**:
  ```bash
  security-scanner --targets "Google:https://www.google.com"
  ```
- **Scan Multiple Targets**:
  ```bash
  security-scanner --targets "Google:https://www.google.com" "Microsoft:https://www.microsoft.com"
  ```
- **Check Version**:
  ```bash
  security-scanner --version
  ```
  Output: `Security Scanner 0.1.0`
- **View Help**:
  ```bash
  security-scanner --help
  ```
  Displays options and examples.

## Example Output

```
=============================================
  Starting passive security reconnaissance...
=============================================
===== Scanning Google (https://www.google.com) =====
Discovering subdomains for www.google.com...
Found 5 domains/subdomains for www.google.com
Beginning parallel scan of all 5 domains/subdomains...
  ✓ Completed scan of www.google.com
  ✓ Completed scan of mail.google.com
...

Security Posture Overview:
------------------------
 Google:
   Main Domain: www.google.com
   Total Subdomains Found: 5
   Successful Scans: 5
   Failed Scans: 0
   Average Security Score: 7.5/10
   Top Issues:
     - DMARC record not found (Found in 5 domains)
   Top Strengths:
     - All recommended security headers implemented (Found in 3 domains)
```

## Requirements

- **Python**: 3.6 or higher
- **Git**: To clone the repository
- **Internet Connection**: For DNS queries and Certificate Transparency lookups

## Notes

- **Passive Only**: This tool does not perform active scans or tests requiring permission—it’s 100% legal and non-intrusive.
- **Subdomain Visibility**: Some discovered subdomains (e.g., dev, int) may be internal and not publicly accessible.
- **Warnings**: You might see:
  - `crt.sh returned status code 429`: Rate limit hit; try again later.
  - DNS errors like `The DNS response does not contain an answer`: Normal for subdomains without TXT/MX/NS records.

## Troubleshooting

- **Command Not Found**: Ensure you ran `pip install .` in the `security_scanner` directory and your Python environment’s `bin/` is in your `PATH`.
- **Dependency Errors**: Verify all libraries installed correctly (`pip list` to check).
- **Anaconda Users**: Use `conda activate your_env` before installing if in a specific environment.

## License

This project is licensed under the MIT License - see `LICENSE` for details.

## Contributing

- Found a bug? Open an issue on this GitHub repository.
- Want to improve it? Fork the repo and submit a pull request!

## Author

Created by **Perly Dahan** - feel free to connect or suggest features!

