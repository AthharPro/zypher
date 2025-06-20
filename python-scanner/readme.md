# Zypher - CI/CD Pipeline Vulnerability Scanner

Zypher is a tool for scanning CI/CD pipeline configuration files (such as GitHub Actions, GitLab CI/CD, etc.) for vulnerabilities and best practice violations. It focuses on the OWASP Top 10 CI/CD Security Risks.

## Features

- Detects hardcoded credentials and secrets in pipeline configurations
- Identifies command injection vulnerabilities in pipeline scripts
- Checks for dependency chain abuse vulnerabilities
- Scans for other OWASP Top 10 CI/CD Security Risks
- Generates detailed reports with line numbers and remediation suggestions
- Supports multiple pipeline formats (GitHub Actions, GitLab CI/CD, Azure Pipelines, etc.)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-username/Zypher-CICD-pipeline-vuln-scanner.git
   cd Zypher-CICD-pipeline-vuln-scanner/python-scanner
   ```

2. Install dependencies:
   ```
   pip install -r requirments.txt
   ```

## Usage

### Basic Usage

Scan a single pipeline configuration file:

```
python cli.py -f path/to/pipeline.yml
```

Scan all pipeline files in a directory:

```
python cli.py -d path/to/directory
```

### Advanced Options

```
usage: cli.py [-h] (-f FILE | -d DIRECTORY) [-c CONFIG] [-o OUTPUT]
               [-r {text,json}] [-v] [-s]

Zypher - CI/CD Pipeline Configuration Vulnerability Scanner

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to a CI/CD pipeline configuration file to scan
  -d DIRECTORY, --directory DIRECTORY
                        Path to a directory containing pipeline configuration files to scan
  -c CONFIG, --config CONFIG
                        Path to scanner configuration file
  -o OUTPUT, --output OUTPUT
                        Path to write the report to (default: stdout)
  -r {text,json}, --report-format {text,json}
                        Report format (default: text)
  -v, --verbose         Enable verbose output
  -s, --sequential      Display findings sequentially with loading animations

Examples:
  python cli.py -f pipeline.yml
  python cli.py -f .github/workflows/ci.yml -o report.json -f json
  python cli.py -d ./pipelines -r text
```

## Example Reports

### Text Report

```
================================================================================
ZYPHER CI/CD PIPELINE VULNERABILITY SCAN REPORT
Generated on: 2025-06-19 14:30:45
Total findings: 3
--------------------------------------------------------------------------------
Severity breakdown:
  CRITICAL: 1
  HIGH: 1
  MEDIUM: 1
  LOW: 0
================================================================================

1. [CRITICAL] CICD-VULN-006: Hardcoded credential found in environment variable 'DATABASE_PASSWORD'
   Location: sample_pipeline.yml:8
   Code snippet: DATABASE_PASSWORD: "supersecretpassword123"
   Recommendation: Move the DATABASE_PASSWORD to a secret management service and reference it securely

2. [HIGH] CICD-VULN-004: Potentially unsafe command execution with dynamic input
   Location: sample_pipeline.yml:46
   Code snippet: eval "kubectl deploy ${APP_NAME}"
   Recommendation: Avoid using eval, exec or similar constructs with untrusted input; validate and sanitize inputs

3. [MEDIUM] CICD-VULN-003: Action only pinned to major version: actions/setup-node@v1
   Location: sample_pipeline.yml:21
   Code snippet: uses: actions/setup-node@v1
   Recommendation: Pin to exact version using a commit SHA for better security
```

### JSON Report

```json
[
  {
    "rule_id": "CICD-VULN-006",
    "severity": "CRITICAL",
    "description": "Hardcoded credential found in environment variable 'DATABASE_PASSWORD'",
    "line_number": 8,
    "filepath": "/path/to/sample_pipeline.yml",
    "snippet": "DATABASE_PASSWORD: \"supersecretpassword123\"",
    "recommendation": "Move the DATABASE_PASSWORD to a secret management service and reference it securely",
    "confidence": "HIGH"
  },
  ...
]
```

## Custom Rules

You can create custom vulnerability detection rules by:

1. Create a new Python file in the `zypher_scanner/scanner/rules/` directory
2. Define a new rule class that inherits from `BaseRule`
3. Implement the `scan` method to detect vulnerabilities
4. Add rule metadata to `data/rule_metadata.json`

Example:

```python
from .base_rule import BaseRule, Finding

class MyCustomRule(BaseRule):
    def scan(self, pipeline_data, file_lines, file_path):
        findings = []
        # Logic to detect vulnerabilities
        return findings
```

## License

MIT