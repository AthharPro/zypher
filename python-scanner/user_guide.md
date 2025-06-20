# Zypher CI/CD Pipeline Vulnerability Scanner: User Guide

## Introduction

The Zypher CI/CD Pipeline Vulnerability Scanner is a tool designed to detect security vulnerabilities and best practice violations in CI/CD pipeline configuration files. It's built around the OWASP Top 10 CI/CD Security Risks and provides actionable feedback for securing your pipelines.

## Code Structure and Architecture

The scanner follows a modular architecture:

1. **Parser (`parser.py`)**: Handles reading and parsing pipeline configuration files (YAML)

2. **Engine (`engine.py`)**: Coordinates the scanning process, loads rules, and generates reports

3. **Rules (`rules/`)**: Individual vulnerability detection rules, each focusing on a specific vulnerability type

4. **CLI (`cli.py`)**: Command-line interface for running scans

5. **Utilities (`utils.py`)**: Helper functions for formatting reports and other common tasks

## Understanding the Core Components

### 1. Base Rule

All rules inherit from the `BaseRule` class in `base_rule.py`. Each rule must implement a `scan()` method that accepts the pipeline data, file lines, and file path, and returns a list of findings.

```python
def scan(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
    # Analyze the pipeline data and detect vulnerabilities
    findings = []
    # Add Finding objects to the findings list
    return findings
```

### 2. The Finding Class

The `Finding` class represents a detected vulnerability:

- `rule_id`: Unique identifier for the rule
- `severity`: Severity level of the vulnerability (LOW, MEDIUM, HIGH, CRITICAL)
- `description`: Description of the vulnerability
- `line_number`: Line number in the file where the vulnerability was found
- `filepath`: Path to the file
- `snippet`: Code snippet containing the vulnerability
- `recommendation`: Suggested fix for the vulnerability

### 3. Scanner Engine

The `ScannerEngine` class coordinates the scanning process:

1. Loads and initializes all rule classes
2. Parses the pipeline configuration file
3. Runs each rule against the parsed pipeline data
4. Collects and organizes findings
5. Generates a formatted report

### 4. CLI

The command-line interface provides a user-friendly way to run the scanner:

- `-f/--file`: Scan a single file
- `-d/--directory`: Scan all pipeline files in a directory
- `-o/--output`: Write the report to a file
- `-r/--report-format`: Specify report format (text/json)
- `-v/--verbose`: Enable verbose output

## How the Rules Work

### Rule: Insufficient Credential Hygiene

This rule scans for hardcoded credentials and other secret management issues:

1. Searches for environment variables that might contain secrets
2. Looks for credential patterns in command lines
3. Detects unprotected uses of secrets in commands

### Rule: Poisoned Pipeline Execution

Focuses on command injection vulnerabilities:

1. Detects dangerous command patterns (`eval`, `exec`, etc.)
2. Identifies unsafe use of variables in command contexts
3. Checks for direct use of untrusted inputs in commands

### Rule: Dependency Chain Abuse

Identifies insecure dependency management:

1. Checks for unpinned action versions
2. Looks for package installations without lockfiles
3. Detects use of unpinned dependency versions

### Rule: Inadequate IAM

Analyzes identity and access management issues:

1. Checks for missing or overly permissive permissions
2. Identifies problematic cloud credential usage
3. Detects use of direct access keys instead of roles

### Rule: Improper Artifact Integrity Validation

Examines artifact signing and verification practices:

1. Checks for Docker image building/pushing without scanning
2. Detects missing artifact signing steps
3. Identifies missing SBOM generation

## Adding New Rules

To add a new rule:

1. Create a new file in the `rules/` directory (e.g., `rule_my_custom_check.py`)
2. Define a class that inherits from `BaseRule`
3. Implement the `scan()` method
4. Add rule metadata to `rule_metadata.json`

## Common Use Cases

### 1. Pre-commit Hook

Add the scanner to your pre-commit hooks to catch vulnerabilities before they're committed:

```yaml
- repo: local
  hooks:
    - id: zypher-scan
      name: Zypher CI/CD Pipeline Scanner
      entry: python path/to/cli.py
      args: ["-f", ".github/workflows/ci.yml"]
      language: system
```

### 2. CI Pipeline Integration

Add a step in your CI pipeline to scan other pipeline configurations:

```yaml
- name: Scan CI/CD configurations
  run: python path/to/cli.py -d .github/workflows -o scan-report.json -r json
```

### 3. Regular Security Audits

Use the scanner as part of regular security audits to identify vulnerabilities in your CI/CD pipelines:

```bash
python cli.py -d path/to/pipelines -o audit-report.txt
```

## Customizing the Scanner

The `config.json` file allows you to customize scanner behavior:

- `severity_threshold`: Minimum severity level to report
- `enabled_rules`: List of rules to enable (empty means all)
- `disabled_rules`: List of rules to disable
- `report_format`: Default report format
- `max_findings`: Maximum number of findings to report

## Best Practices

1. **Regular Scanning**: Scan your pipeline configurations regularly, especially after changes
2. **Integrate with CI/CD**: Include scanning as part of your CI/CD process
3. **Address Critical Findings First**: Focus on CRITICAL and HIGH severity findings first
4. **Implement Suggested Fixes**: Use the recommendations to fix identified issues
5. **Custom Rules**: Create custom rules for your organization's specific security requirements
