import re
from typing import Dict, List, Any
import yaml

from .base_rule import BaseRule, Finding

class RuleInsufficientCredentialHygiene(BaseRule):
    def __init__(self):
        super().__init__()
        # Regex patterns for detecting potential hardcoded credentials
        self.credential_patterns = [
            r"password[\"\':\s]*=[\"\'\s]*[a-zA-Z0-9_\-\+\.\@\#\$\%\^\&\*\(\)\[\]\{\}\<\>\~\`]{3,}",
            r"pwd[\"\':\s]*=[\"\'\s]*[a-zA-Z0-9_\-\+\.\@\#\$\%\^\&\*\(\)\[\]\{\}\<\>\~\`]{3,}",
            r"passwd[\"\':\s]*=[\"\'\s]*[a-zA-Z0-9_\-\+\.\@\#\$\%\^\&\*\(\)\[\]\{\}\<\>\~\`]{3,}",
            r"apikey[\"\':\s]*=[\"\'\s]*[a-zA-Z0-9_\-\+\.\@\#\$\%\^\&\*\(\)\[\]\{\}\<\>\~\`]{3,}",
            r"api_key[\"\':\s]*=[\"\'\s]*[a-zA-Z0-9_\-\+\.\@\#\$\%\^\&\*\(\)\[\]\{\}\<\>\~\`]{3,}",
            r"secret[\"\':\s]*=[\"\'\s]*[a-zA-Z0-9_\-\+\.\@\#\$\%\^\&\*\(\)\[\]\{\}\<\>\~\`]{3,}",
            r"token[\"\':\s]*=[\"\'\s]*[a-zA-Z0-9_\-\+\.\@\#\$\%\^\&\*\(\)\[\]\{\}\<\>\~\`]{3,}"
        ]
        
        # AWS credential patterns
        self.aws_key_pattern = r"(?:ACCESS|SECRET)_?KEY(?:_ID)?[\"\':\s]*=[\"\'\s]*(?:AKIA)[a-zA-Z0-9]{16,}"
        
    def scan(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan for hardcoded credentials and poor credential management practices.
        
        Args:
            pipeline_data: The parsed YAML pipeline configuration
            file_lines: The raw file content as a list of strings
            file_path: Path to the file being scanned
            
        Returns:
            A list of Finding objects for detected vulnerabilities
        """
        findings = []
        
        # Check for hardcoded credentials in environment variables section
        if "env" in pipeline_data:
            env_vars = pipeline_data["env"]
            for key, value in env_vars.items():
                if isinstance(value, str) and self._is_credential_key(key):
                    # Find the line number for this environment variable
                    line_num = self._find_line_number(file_lines, key, value)
                    if line_num:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            description=f"Hardcoded credential found in environment variable '{key}'",
                            line_number=line_num,
                            filepath=file_path,
                            snippet=file_lines[line_num - 1].strip(),
                            recommendation=f"Move the {key} to a secret management service and reference it securely"
                        ))
        
        # Scan through all lines for credential patterns
        for i, line in enumerate(file_lines):
            # Check for credential patterns
            for pattern in self.credential_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        description="Potential hardcoded credential found in pipeline",
                        line_number=i + 1,  # Convert to 1-based line numbers
                        filepath=file_path,
                        snippet=line.strip(),
                        recommendation="Store credentials in a secret management service"
                    ))
                    break  # Avoid multiple findings for the same line
                    
            # Check for AWS key patterns
            if re.search(self.aws_key_pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    description="AWS access key found in pipeline configuration",
                    line_number=i + 1,
                    filepath=file_path,
                    snippet=line.strip(),
                    recommendation="Use AWS role-based authentication instead of access keys"
                ))
        
        # Check for unprotected uses of secrets
        self._check_for_unprotected_secrets(pipeline_data, file_lines, file_path, findings)
        
        return findings
        
    def _is_credential_key(self, key: str) -> bool:
        """Check if a key name suggests it might contain credentials"""
        credential_keywords = ["password", "secret", "token", "key", "pwd", "auth", "api", "credential"]
        key_lower = key.lower()
        return any(keyword in key_lower for keyword in credential_keywords)
        
    def _find_line_number(self, file_lines: List[str], key: str, value: str) -> int:
        """Find the line number for a key-value pair in the file"""
        for i, line in enumerate(file_lines):
            if key in line and str(value) in line:
                return i + 1  # Convert to 1-based line numbers
        return None
        
    def _check_for_unprotected_secrets(self, pipeline_data: Dict[str, Any], file_lines: List[str], 
                                     file_path: str, findings: List[Finding]) -> None:
        """Check for secrets used without proper protection"""
        # Look for jobs and steps
        if "jobs" in pipeline_data:
            for job_name, job_config in pipeline_data["jobs"].items():
                if "steps" in job_config:
                    for i, step in enumerate(job_config["steps"]):
                        if "run" in step and isinstance(step["run"], str):
                            # Look for unprotected secrets usage in shell commands
                            command = step["run"]
                            if "echo" in command and ("secret" in command.lower() or "${{" in command):
                                # Find the line number
                                line_num = None
                                for j, line in enumerate(file_lines):
                                    if "run:" in line and "echo" in line:
                                        for k in range(j, min(j + 5, len(file_lines))):
                                            if "echo" in file_lines[k] and ("secret" in file_lines[k].lower() or "${{" in file_lines[k]):
                                                line_num = k + 1
                                                break
                                        if line_num:
                                            break
                                
                                if line_num:
                                    findings.append(Finding(
                                        rule_id=self.rule_id,
                                        severity=self.severity,
                                        description="Potential secret exposure through echo command",
                                        line_number=line_num,
                                        filepath=file_path,
                                        snippet=file_lines[line_num - 1].strip(),
                                        recommendation="Avoid printing secrets in pipeline commands"
                                    ))
