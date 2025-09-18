# SSH Failed Attempts Parser

This project was entirely done by Cursor! No deception here,  I was curious of the capability of AI when it comes to programming and cybersecurity, so gave it a whirl here. It coded this in probably about an hour, and I'm sure it can do much more if given the right prompts. Pretty cool!

This is a comprehensive bash script to parse SSH log files for failed login attempts. This tool helps security administrators identify potential brute force attacks and unauthorized access attempts.

## Features

- **Multiple Log Format Support**: Handles various SSH log formats including auth.log, secure, and messages
- **Flexible Filtering**: Filter by date ranges and IP whitelists
- **Detailed Reporting**: Provides both detailed and summary reports
- **IP Whitelisting**: Exclude trusted IP addresses from analysis
- **Color-coded Output**: Easy-to-read colored terminal output
- **Multiple Output Formats**: Output to terminal or save to file

## Supported Log Patterns

The script detects the following failed SSH attempt patterns:
- Failed password attempts
- Invalid user attempts
- Connection closed by invalid user
- PAM authentication failures
- Failed keyboard-interactive/pam attempts

## Installation

1. Download the script:
```bash
wget https://raw.githubusercontent.com/EthanDann/SSH-Log-Parser/main/ssh_failed_attempts_parser.sh
```

2. Make it executable:
```bash
chmod +x ssh_failed_attempts_parser.sh
```

3. Run the script:
```bash
./ssh_failed_attempts_parser.sh --help
```

## Usage

### Basic Usage

Parse the default auth.log file:
```bash
./ssh_failed_attempts_parser.sh
```

Parse a specific log file:
```bash
./ssh_failed_attempts_parser.sh /var/log/auth.log
```

Parse multiple log files:
```bash
./ssh_failed_attempts_parser.sh /var/log/auth.log /var/log/secure
```

### Advanced Options

**Output to file:**
```bash
./ssh_failed_attempts_parser.sh -o failed_attempts.txt /var/log/auth.log
```

**Show summary only:**
```bash
./ssh_failed_attempts_parser.sh -s /var/log/auth.log
```

**Filter by date range:**
```bash
./ssh_failed_attempts_parser.sh -f "2024-01-01" -t "2024-01-31" /var/log/auth.log
```

**Use IP whitelist:**
```bash
./ssh_failed_attempts_parser.sh -w whitelist.txt /var/log/auth.log
```

**Verbose output:**
```bash
./ssh_failed_attempts_parser.sh -v /var/log/auth.log
```

### Command Line Options

| Option | Long Option | Description |
|--------|-------------|-------------|
| `-h` | `--help` | Show help message |
| `-o FILE` | `--output FILE` | Output results to FILE |
| `-v` | `--verbose` | Enable verbose output |
| `-s` | `--summary` | Show summary only |
| `-f DATE` | `--from-date DATE` | Filter from DATE (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS) |
| `-t DATE` | `--to-date DATE` | Filter to DATE (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS) |
| `-w FILE` | `--whitelist FILE` | File containing IP addresses to whitelist |
| `-a` | `--auth-log` | Parse /var/log/auth.log |
| `-m` | `--messages` | Parse /var/log/messages |
| `-s` | `--secure` | Parse /var/log/secure |

## Examples

### Example 1: Basic Analysis
```bash
./ssh_failed_attempts_parser.sh sample_auth.log
```

Output:
```
[INFO] Starting SSH failed attempts parser...
[INFO] Log files to process: sample_auth.log
[INFO] Parsing sample_auth.log...
Timestamp: Jan 15 10:30:15
IP Address: 192.168.1.100
Username: admin
Message: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
---
...
```

### Example 2: Summary Report
```bash
./ssh_failed_attempts_parser.sh -s sample_auth.log
```

Output:
```
=== SSH FAILED ATTEMPTS SUMMARY ===
Total failed attempts: 20
Unique attacking IPs: 5
Unique usernames targeted: 6

=== TOP 10 ATTACKING IP ADDRESSES ===
6 attempts from 192.168.1.100
4 attempts from 203.0.113.45
3 attempts from 10.0.0.50
3 attempts from 198.51.100.25
2 attempts from 172.16.0.100

=== TOP 10 TARGETED USERNAMES ===
5 attempts for user 'admin'
4 attempts for user 'john'
3 attempts for user 'test'
2 attempts for user 'root'
2 attempts for user 'guest'
1 attempts for user 'hacker'
```

### Example 3: With Whitelist
```bash
./ssh_failed_attempts_parser.sh -w whitelist.txt -s sample_auth.log
```

This will exclude attempts from IPs in whitelist.txt (10.0.0.50 and 172.16.0.100).

## Whitelist File Format

Create a text file with one IP address per line:
```
10.0.0.50
172.16.0.100
192.168.1.1
```

## Log File Locations

Common SSH log file locations:
- **Ubuntu/Debian**: `/var/log/auth.log`
- **CentOS/RHEL**: `/var/log/secure`
- **Systemd systems**: `/var/log/messages`

## Security Considerations

1. **File Permissions**: Ensure the script has appropriate permissions to read log files
2. **Whitelist Management**: Keep your IP whitelist updated with trusted addresses
3. **Regular Monitoring**: Run the script regularly to monitor for new attack patterns
4. **Log Rotation**: Be aware of log rotation which may affect historical analysis

## Troubleshooting

### Common Issues

**Permission Denied:**
```bash
sudo ./ssh_failed_attempts_parser.sh /var/log/auth.log
```

**No failed attempts found:**
- Check if the log file contains SSH entries
- Verify the log file path is correct
- Ensure the log file is readable

**Date filtering not working:**
- Use the correct date format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS
- Ensure the date command is available on your system

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the examples
3. Open an issue on GitHub

## Changelog

### Version 1.0.0
- Initial release
- Support for multiple log formats
- Date filtering capabilities
- IP whitelisting
- Summary and detailed reporting
- Color-coded output 
