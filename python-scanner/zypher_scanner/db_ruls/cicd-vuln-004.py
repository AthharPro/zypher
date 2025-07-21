import re
from typing import Dict, List, Any

from .base_rules import BaseRule, Finding

class RulePoisonedPipelineExecution(BaseRule):
    METADATA = {
        "rule_id": "CICD-VULN-004",
        "rule_name": "Poisoned Pipeline Execution",
        "severity": "HIGH"
    }

    def __init__(self):
        super().__init__()
        self.dangerous_commands = [
            r"eval\s+[\"\']?.*\$\{\{",   # eval with variable
            r"exec\s+[\"\']?.*\$\{\{",   # exec with variable
            r"source\s+[\"\']?.*\$\{\{", # source with variable
            r"\$\(\s*.*\$\{\{",          # command substitution with variable
            r"\`.*\$\{\{"                # backtick command substitution with variable
        ]
        self.unsafe_input_patterns = [
            r"github\.event\..+",         # Directly using GitHub event data in commands
            r"github\.(?:head|base)_ref", # Using reference names directly
            r"github\.(?:actor|user)"     # Using user-provided values directly
        ]

    def get_severity(self):
        return self.METADATA["severity"]

    def scan(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan for command injection vulnerabilities in pipeline scripts.
        """
        findings = []
        # Check for unsafe command execution in all job steps
        if "jobs" in pipeline_data:
            for job_name, job_config in pipeline_data["jobs"].items():
                if "steps" in job_config:
                    self._scan_steps_for_command_injection(
                        job_name, job_config["steps"], file_lines, file_path, findings
                    )
        return findings

    def _scan_steps_for_command_injection(self, job_name: str, steps: List[Dict[str, Any]],
                                          file_lines: List[str], file_path: str,
                                          findings: List[Finding]) -> None:
        """Scan job steps for command injection vulnerabilities"""
        for step_index, step in enumerate(steps):
            if "run" in step and isinstance(step["run"], str):
                run_command = step["run"]
                line_num = self._find_run_command_line(file_lines, run_command, step)

                # Check for dangerous command patterns
                for pattern in self.dangerous_commands:
                    if re.search(pattern, run_command):
                        findings.append(Finding(
                            rule_id=self.METADATA["rule_id"],
                            severity=self.get_severity(),
                            description="Potentially unsafe command execution with dynamic input",
                            line_number=line_num,
                            filepath=file_path,
                            snippet=self._get_snippet(file_lines, line_num),
                            recommendation="Avoid using eval, exec or similar constructs with untrusted input; validate and sanitize inputs"
                        ))

                # Check for direct use of unsafe inputs
                for pattern in self.unsafe_input_patterns:
                    if re.search(pattern, run_command):
                        match = re.search(pattern, run_command)
                        if match:
                            unsafe_var = match.group(0)
                            if self._is_in_command_context(run_command, unsafe_var):
                                findings.append(Finding(
                                    rule_id=self.METADATA["rule_id"],
                                    severity=self.get_severity(),
                                    description=f"Untrusted input '{unsafe_var}' used in command context",
                                    line_number=line_num,
                                    filepath=file_path,
                                    snippet=self._get_snippet(file_lines, line_num),
                                    recommendation="Validate and sanitize user-provided input before using it in commands"
                                ))

    def _find_run_command_line(self, file_lines: List[str], run_command: str, step: Dict[str, Any]) -> int:
        """Find the approximate line number for a run command"""
        step_name = step.get("name", "")

        # First try to find the step by name
        if step_name:
            for i, line in enumerate(file_lines):
                if f"name: {step_name}" in line:
                    # Look for run: in the next few lines
                    for j in range(i+1, min(i+5, len(file_lines))):
                        if "run:" in file_lines[j]:
                            return j + 1  # The line after 'run:' is likely our command

        # If that fails, try to find the run command directly
        command_lines = run_command.strip().split("\n")
        if command_lines:
            first_command_line = command_lines[0].strip()
            for i, line in enumerate(file_lines):
                if "run:" in line and i+1 < len(file_lines) and first_command_line in file_lines[i+1]:
                    return i + 2  # The line after 'run:'

        # If all else fails, search for any part of the command
        for i, line in enumerate(file_lines):
            for cmd_part in run_command.split("\n"):
                if cmd_part.strip() in line:
                    return i + 1

        return 1  # Default to first line if we can't find it

    def _get_snippet(self, file_lines: List[str], line_num: int) -> str:
        """Get a snippet of the code around the given line number"""
        if line_num < 1 or line_num > len(file_lines):
            return ""
        return file_lines[line_num - 1].strip()

    def _is_in_command_context(self, command: str, variable: str) -> bool:
        """Check if a variable is used in a command execution context"""
        command_contexts = [
            rf"eval.*{re.escape(variable)}",
            rf"exec.*{re.escape(variable)}",
            rf"bash.*{re.escape(variable)}",
            rf"sh.*{re.escape(variable)}",
            rf"`.*{re.escape(variable)}.*`",
            rf"\$\(.*{re.escape(variable)}.*\)"
        ]

        for context in command_contexts:
            if re.search(context, command):
                return True

        # Check if the variable is used directly in a command line
        lines = command.split("\n")
        for line in lines:
            if (line.strip().startswith(variable) or
                "|" + variable in line or
                ";" + variable in line or
                "&&" + variable in line):
                return True

        return False