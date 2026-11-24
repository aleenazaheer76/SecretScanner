# SecretScan – Hardcoded Secrets Scanner

**Author:** Aleena Zaheer

**Department:** Cyber Security

**Track:** Secure Code Review

## 1. Project Overview

SecretScan is a Python-based command-line security tool that detects hardcoded secrets in source code.

The tool helps identify accidentally exposed API keys, tokens, passwords, private key headers and suspicious high-entropy strings.

## 2. Project Objectives

- Identify hardcoded credentials in source code.
- Scan folders and nested directories.
- Detect suspicious random-looking strings.
- Reduce false positives using an allowlist.
- Generate a report containing file paths and line numbers.

## 3. Features

- Recursive folder scanning.
- API key detection.
- Generic token detection.
- Private key header detection.
- Password assignment detection.
- AWS access key detection.
- Shannon entropy analysis.
- Binary file skipping.
- Excluded directory filtering.
- Allowlist filtering.
- Duplicate finding removal.
- Text report generation.

## 4. Technologies Used

- Python 3
- Regular Expressions
- OS module
- Argparse
- Shannon Entropy

## 5. Project Structure

```text
SecretScan/
├── secret_scan.py
├── allowlist.txt
├── report.txt
├── README.md
└── test_repo/
    ├── app.py
    ├── config.py
    ├── keys.txt
    └── database/
        └── settings.py
```

## 6. Requirements

- Python 3 installed.
- Windows or Kali Linux.
- No external Python packages required.

## 7. How to Run

### Windows

```bash
python secret_scan.py test_repo --allowlist allowlist.txt --output report.txt
```

### Kali Linux

```bash
python3 secret_scan.py test_repo --allowlist allowlist.txt --output report.txt
```

## 8. How It Works

1. The scanner walks through the selected directory recursively.
2. It skips binary files and excluded directories.
3. It applies regular expressions to identify known secret patterns.
4. It calculates Shannon entropy for suspicious strings.
5. It filters allowlisted values and duplicate findings.
6. It generates a report with finding counts, file paths and line numbers.

## 9. Testing

The tool is tested using a controlled repository containing fake API keys, tokens, passwords, private key headers and high-entropy strings.

Testing also includes recursive scanning, allowlist filtering, binary file skipping and report generation.

No real credentials or unauthorized repositories are used.

## 10. Defensive Security Lesson

Hardcoded credentials should never be stored directly in source code.

Developers should use environment variables or secure secrets-management systems.

If a genuine credential is exposed, it should be rotated immediately.

## 11. Limitations

SecretScan uses a limited set of regular expressions and an entropy threshold. It may produce false positives or miss unfamiliar secret formats.

It is an educational security tool, not a replacement for production-grade secret-scanning systems.

## 12. Author

Aleena Zaheer

**Project:** SecretScan – Your Own Hardcoded-Secrets Scanner