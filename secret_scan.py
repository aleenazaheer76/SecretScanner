

import os
import re
import math
import argparse


# STEP 2: SECRET DETECTION PATTERNS

PATTERNS = [
    (
        "Private Key",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        0
    ),
    (
        "AWS Access Key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        0
    ),
    (
        "API Key",
        re.compile(
            r"""(?i)\b[A-Za-z0-9_-]*api[_-]?key\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{8,})"""
        ),
        1
    ),
    (
        "Generic Token",
        re.compile(
            r"""(?i)\b[A-Za-z0-9_-]*(?:access[_-]?token|auth[_-]?token|token)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{8,})"""
        ),
        1
    ),
    (
        "Password",
        re.compile(
            r"""(?i)\b[A-Za-z0-9_-]*(?:password|passwd|pwd)\b\s*[:=]\s*["']?([^"' \t,;#]{4,})"""
        ),
        1
    )
]


# STEP 3: EXCLUDED DIRECTORIES

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".idea"
}


# STEP 4: SHANNON ENTROPY

def calculate_entropy(text):

    if not text:
        return 0

    entropy = 0

    for character in set(text):

        probability = text.count(character) / len(text)

        entropy -= probability * math.log2(probability)

    return entropy


# STEP 5: LOAD ALLOWLIST

def load_allowlist(filename):

    allowed = set()

    if not filename or not os.path.isfile(filename):
        return allowed

    with open(filename, "r", encoding="utf-8") as file:

        for line in file:

            value = line.strip()

            if value and not value.startswith("#"):
                allowed.add(value)

    return allowed


# CHECK BINARY FILES

def is_binary(data):

    return b"\x00" in data


# SCAN A SINGLE FILE

def scan_file(filename, root_folder):

    findings = []

    with open(filename, "rb") as file:
        data = file.read()

    if is_binary(data):
        return findings

    content = data.decode("utf-8", errors="replace")

    for line_number, line in enumerate(content.splitlines(), start=1):

        detected_spans = []

        # Detect known patterns

        for category, pattern, group in PATTERNS:

            for match in pattern.finditer(line):

                secret = match.group(group)

                start, end = match.span(group)

                detected_spans.append((start, end))

                findings.append({
                    "category": category,
                    "file": os.path.relpath(filename, root_folder),
                    "line": line_number,
                    "secret": secret,
                    "context": line.strip()
                })

        # Detect high-entropy strings

        candidates = re.finditer(
            r"[A-Za-z0-9_+/=-]{20,}",
            line
        )

        for candidate in candidates:

            secret = candidate.group()

            start, end = candidate.span()

            overlaps = any(
                start < old_end and end > old_start
                for old_start, old_end in detected_spans
            )

            if not overlaps and calculate_entropy(secret) >= 4.0:

                findings.append({
                    "category": "High Entropy",
                    "file": os.path.relpath(filename, root_folder),
                    "line": line_number,
                    "secret": secret,
                    "context": line.strip()
                })

    return findings


# STEP 3: RECURSIVE FOLDER SCANNING

def scan_folder(folder):

    findings = []

    for root, directories, files in os.walk(folder):

        directories[:] = [
            directory for directory in directories
            if directory not in EXCLUDED_DIRS
        ]

        for filename in files:

            filepath = os.path.join(root, filename)

            try:
                findings.extend(scan_file(filepath, folder))

            except (OSError, UnicodeError) as error:
                print("Could not read:", filepath, error)

    return findings


# STEP 5: FILTER ALLOWLIST AND DUPLICATES

def filter_findings(findings, allowlist):

    filtered = []
    seen = set()
    suppressed = 0

    for finding in findings:

        secret = finding["secret"]

        if secret in allowlist:
            suppressed += 1
            continue

        key = (
            finding["file"],
            finding["line"],
            finding["category"],
            secret
        )

        if key not in seen:

            seen.add(key)
            filtered.append(finding)

    return filtered, suppressed


# STEP 6: GENERATE REPORT

def generate_report(findings, suppressed, output):

    counts = {}

    for finding in findings:

        category = finding["category"]

        counts[category] = counts.get(category, 0) + 1

    report = []

    report.append("========== SECRETSCAN REPORT ==========")
    report.append("Total findings: " + str(len(findings)))
    report.append("Suppressed findings: " + str(suppressed))
    report.append("")

    report.append("FINDING COUNTS")

    for category, count in sorted(counts.items()):
        report.append(category + ": " + str(count))

    report.append("")
    report.append("DETAILED FINDINGS")

    for finding in findings:

        secret = finding["secret"]

        context = finding["context"].replace(
            secret, "[REDACTED]"
        )

        report.append("")
        report.append("Category: " + finding["category"])
        report.append("File: " + finding["file"])
        report.append("Line: " + str(finding["line"]))
        report.append("Match: [REDACTED]")
        report.append("Context: " + context)

    report.append("")
    report.append("========== END OF REPORT ==========")

    report_text = "\n".join(report)

    print(report_text)

    with open(output, "w", encoding="utf-8") as file:
        file.write(report_text)

    print("\nReport saved to:", output)


# STEP 6: COMMAND LINE INTERFACE

def main():

    parser = argparse.ArgumentParser(
        description="SecretScan - Hardcoded Secrets Scanner"
    )

    parser.add_argument(
        "folder",
        help="Folder to scan"
    )

    parser.add_argument(
        "--allowlist",
        default="allowlist.txt",
        help="Path to allowlist file"
    )

    parser.add_argument(
        "--output",
        default="report.txt",
        help="Path to save report"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.folder):
        parser.error("The specified folder does not exist.")

    print("Starting SecretScan...")
    print("Scanning folder:", args.folder)

    allowlist = load_allowlist(args.allowlist)

    findings = scan_folder(args.folder)

    findings, suppressed = filter_findings(
        findings, allowlist
    )

    generate_report(
        findings, suppressed, args.output
    )


if __name__ == "__main__":
    main()

    
