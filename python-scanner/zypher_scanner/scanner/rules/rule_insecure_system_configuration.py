import re
from typing import List, Dict, Any, Optional

from .base_rule import BaseRule, Finding


class RuleInsecureSystemConfiguration(BaseRule):
    """
    Rule to detect insecure system configuration in CI/CD pipelines.
    
    This rule identifies:
    1. Usage of deprecated or insecure runner images/versions
    2. Missing security hardening for runners/environments
    3. Misconfigured timeouts or job limits
    4. Uncontrolled script execution sources
    5. Missing security configurations
    """
    
    def __init__(self):
        super().__init__()
    
    def get_severity(self):
        """Return the severity of this rule"""
        return "HIGH"
        
    def scan(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan pipeline data for insecure system configuration issues.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Determine pipeline type
        pipeline_type = self._detect_pipeline_type(pipeline_data)
        
        if pipeline_type == "github":
            findings.extend(self._scan_github_workflow(pipeline_data, file_lines, file_path))
        elif pipeline_type == "gitlab":
            findings.extend(self._scan_gitlab_ci(pipeline_data, file_lines, file_path))
        elif pipeline_type == "azure":
            findings.extend(self._scan_azure_pipeline(pipeline_data, file_lines, file_path))
        elif pipeline_type == "jenkins":
            findings.extend(self._scan_jenkins_pipeline(pipeline_data, file_lines, file_path))
        else:
            # Generic checks for other pipeline types
            findings.extend(self._scan_generic_pipeline(pipeline_data, file_lines, file_path))
        
        return findings
    
    def _detect_pipeline_type(self, pipeline_data: Dict[str, Any]) -> str:
        """
        Detect the type of CI/CD pipeline configuration.
        
        Args:
            pipeline_data: The parsed pipeline data
            
        Returns:
            String indicating pipeline type ("github", "gitlab", "azure", "jenkins", or "unknown")
        """
        if pipeline_data.get("jobs") and (pipeline_data.get("on") or pipeline_data.get("name")):
            return "github"
        elif pipeline_data.get("stages") and (pipeline_data.get("workflow") or pipeline_data.get(".gitlab-ci.yml")):
            return "gitlab"
        elif pipeline_data.get("pool") or pipeline_data.get("trigger") or pipeline_data.get("resources"):
            return "azure"
        elif pipeline_data.get("pipeline") and (pipeline_data.get("agent") or pipeline_data.get("stages")):
            return "jenkins"
        else:
            return "unknown"
    
    def _scan_github_workflow(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan GitHub Actions workflows for insecure system configuration issues.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for missing timeout settings
        has_timeout = False
        if "defaults" in pipeline_data and "run" in pipeline_data["defaults"]:
            has_timeout = "timeout-minutes" in pipeline_data["defaults"]["run"]
        
        if not has_timeout:
            # Check if individual jobs have timeouts
            has_any_job_timeout = False
            if "jobs" in pipeline_data:
                for job_name, job_data in pipeline_data["jobs"].items():
                    if isinstance(job_data, dict) and "timeout-minutes" in job_data:
                        has_any_job_timeout = True
                        break
            
            if not has_any_job_timeout:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.get_severity(),
                    description="Missing timeout configuration for workflow jobs",
                    line_number=1,
                    filepath=file_path,
                    snippet=file_lines[0].strip(),
                    recommendation="Add timeout-minutes configuration to prevent runaway jobs from consuming resources"
                ))
        
        # Check for unsafe version of ubuntu runner (if specified)
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if isinstance(job_data, dict) and "runs-on" in job_data:
                    runner = job_data["runs-on"]
                    if isinstance(runner, str):
                        runner_line = self._find_line_with_content(file_lines, f"runs-on: {runner}", 0)
                        
                        # Check for deprecated or outdated runners
                        if runner in ["ubuntu-18.04", "ubuntu-16.04", "ubuntu-latest"]:
                            if runner_line >= 0:
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    severity=self.get_severity(),
                                    description=f"Using potentially outdated or suboptimal runner image: {runner}",
                                    line_number=runner_line + 1,
                                    filepath=file_path,
                                    snippet=file_lines[runner_line].strip(),
                                    recommendation="Specify a pinned runner version (e.g., ubuntu-22.04) instead of 'latest' or outdated versions"
                                ))
        
        # Check for missing 'continue-on-error' for non-critical jobs
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                # Skip deployment jobs - they should fail safely
                if "deploy" in job_name.lower():
                    continue
                    
                if isinstance(job_data, dict) and "continue-on-error" not in job_data:
                    if self._is_test_or_scan_job(job_name, job_data):
                        line_number = self._find_line_with_content(file_lines, f"{job_name}:", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity="MEDIUM",
                                description=f"Test/scan job '{job_name}' lacks continue-on-error setting",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Consider adding 'continue-on-error: true' for non-critical jobs like tests or scans to make failures non-blocking"
                            ))
                    
        # Check for potentially insecure actions execution
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if isinstance(job_data, dict) and "steps" in job_data:
                    for step_idx, step in enumerate(job_data["steps"]):
                        if isinstance(step, dict):
                            # Check for unsafe curl pipe bash patterns
                            if "run" in step and isinstance(step["run"], str):
                                cmd = step["run"].lower()
                                if (("curl" in cmd or "wget" in cmd) and 
                                    ("sh -" in cmd or "bash -" in cmd or "| sh" in cmd or "| bash" in cmd)):
                                    line_number = self._find_step_line_number(file_lines, job_name, step_idx)
                                    if line_number >= 0:
                                        findings.append(Finding(
                                            rule_id=self.rule_id,
                                            severity=self.get_severity(),
                                            description="Insecure execution of scripts from network sources",
                                            line_number=line_number + 1,
                                            filepath=file_path,
                                            snippet=file_lines[line_number].strip(),
                                            recommendation="Avoid piping network content directly to a shell. Download, verify checksum/signature, then execute."
                                        ))
        
        # Check for missing concurrency limits
        if "concurrency" not in pipeline_data:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity="MEDIUM",
                description="Missing concurrency limits in workflow",
                line_number=1,
                filepath=file_path,
                snippet=file_lines[0].strip(),
                recommendation="Add concurrency limits to prevent multiple deployments running simultaneously and causing race conditions"
            ))
        
        return findings
    
    def _scan_gitlab_ci(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan GitLab CI/CD pipelines for insecure system configuration issues.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for missing default timeout settings
        has_default_timeout = False
        if "default" in pipeline_data and "timeout" in pipeline_data["default"]:
            has_default_timeout = True
        
        if not has_default_timeout:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity="MEDIUM",
                description="Missing default timeout configuration",
                line_number=1,
                filepath=file_path,
                snippet=file_lines[0].strip(),
                recommendation="Add a default.timeout configuration to prevent jobs from running indefinitely"
            ))
        
        # Check for unsafe use of privileged containers
        for key, value in pipeline_data.items():
            if not isinstance(value, dict):
                continue
                
            # Skip reserved keywords
            if key in ["stages", "variables", "workflow", "default", "include"]:
                continue
            
            # Check for privileged flag
            if value.get("services") and isinstance(value["services"], list):
                for i, service in enumerate(value["services"]):
                    if isinstance(service, dict) and service.get("privileged") is True:
                        line_number = self._find_job_services_line(file_lines, key, i)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=self.get_severity(),
                                description=f"Job '{key}' uses privileged container without security constraints",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Avoid using privileged containers or use with caution. Implement additional security controls."
                            ))
            
            # Check for DIND (Docker-in-Docker) usage without security measures
            if (value.get("image") and "docker:dind" in str(value["image"])) or \
               (value.get("services") and isinstance(value["services"], list) and 
                any("docker:dind" in str(service) for service in value["services"] if isinstance(service, (str, dict)))):
                
                # Find line with docker:dind
                dind_line = -1
                for i, line in enumerate(file_lines):
                    if "docker:dind" in line:
                        dind_line = i
                        break
                
                if dind_line >= 0:
                    # Check if TLS is explicitly configured
                    has_tls_config = False
                    for i in range(max(0, dind_line - 5), min(len(file_lines), dind_line + 10)):
                        if "DOCKER_TLS" in file_lines[i]:
                            has_tls_config = True
                            break
                    
                    if not has_tls_config:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.get_severity(),
                            description="Docker-in-Docker usage without TLS protection",
                            line_number=dind_line + 1,
                            filepath=file_path,
                            snippet=file_lines[dind_line].strip(),
                            recommendation="Configure TLS for Docker-in-Docker services by setting DOCKER_TLS_CERTDIR variable"
                        ))
        
        # Check for unsafe script execution
        for key, value in pipeline_data.items():
            if not isinstance(value, dict) or key in ["stages", "variables", "workflow", "default", "include"]:
                continue
            
            if "script" in value:
                scripts = value["script"]
                script_lines = scripts if isinstance(scripts, list) else [scripts] if isinstance(scripts, str) else []
                
                for script in script_lines:
                    if isinstance(script, str) and (("curl" in script.lower() or "wget" in script.lower()) and 
                                                   ("sh -" in script.lower() or "bash -" in script.lower())):
                        line_number = self._find_script_line(file_lines, key, script)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=self.get_severity(),
                                description="Insecure execution of scripts from network sources",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Avoid piping network content directly to a shell. Download, verify checksum/signature, then execute."
                            ))
        
        return findings
    
    def _scan_azure_pipeline(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan Azure DevOps pipelines for insecure system configuration issues.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for missing timeouts
        has_timeout = False
        if "jobs" in pipeline_data:
            for job in pipeline_data["jobs"] if isinstance(pipeline_data["jobs"], list) else []:
                if isinstance(job, dict) and "timeoutInMinutes" in job:
                    has_timeout = True
                    break
                    
        if not has_timeout and "stages" in pipeline_data:
            for stage in pipeline_data["stages"] if isinstance(pipeline_data["stages"], list) else []:
                if isinstance(stage, dict) and "timeoutInMinutes" in stage:
                    has_timeout = True
                    break
                    
        if not has_timeout and "timeoutInMinutes" not in pipeline_data:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity="MEDIUM",
                description="Missing timeout configuration in pipeline",
                line_number=1,
                filepath=file_path,
                snippet=file_lines[0].strip(),
                recommendation="Add timeoutInMinutes at the pipeline, stage, or job level to prevent runaway processes"
            ))
        
        # Check for use of insecure or outdated VM images
        if "pool" in pipeline_data and "vmImage" in pipeline_data["pool"]:
            vm_image = pipeline_data["pool"]["vmImage"]
            vm_line = self._find_line_with_content(file_lines, f"vmImage: {vm_image}", 0)
            
            if isinstance(vm_image, str):
                # Check for outdated images
                if vm_image.startswith(("ubuntu-18", "windows-2016", "macOS-10")):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.get_severity(),
                        description=f"Using outdated VM image: {vm_image}",
                        line_number=vm_line + 1 if vm_line >= 0 else 1,
                        filepath=file_path,
                        snippet=file_lines[vm_line].strip() if vm_line >= 0 else "",
                        recommendation="Update to a more recent VM image with security updates"
                    ))
                # Check for unspecific image references
                elif vm_image.endswith("latest"):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity="MEDIUM",
                        description=f"Using non-specific 'latest' VM image tag: {vm_image}",
                        line_number=vm_line + 1 if vm_line >= 0 else 1,
                        filepath=file_path,
                        snippet=file_lines[vm_line].strip() if vm_line >= 0 else "",
                        recommendation="Pin to a specific VM image version for reproducibility and security"
                    ))
        
        # Check for unsafe script execution in tasks
        if "jobs" in pipeline_data:
            for job_idx, job in enumerate(pipeline_data["jobs"] if isinstance(pipeline_data["jobs"], list) else []):
                if isinstance(job, dict) and "steps" in job:
                    for step_idx, step in enumerate(job["steps"] if isinstance(job["steps"], list) else []):
                        if not isinstance(step, dict):
                            continue
                            
                        # Check for inline scripts with unsafe patterns
                        if step.get("task") == "Bash" or step.get("task") == "PowerShell":
                            script_input = step.get("inputs", {}).get("script", "")
                            if isinstance(script_input, str) and (("curl" in script_input.lower() or "wget" in script_input.lower()) and 
                                                       ("sh -" in script_input.lower() or "bash -" in script_input.lower())):
                                line_number = self._find_azure_task_line(file_lines, job_idx, step_idx)
                                if line_number >= 0:
                                    findings.append(Finding(
                                        rule_id=self.rule_id,
                                        severity=self.get_severity(),
                                        description="Insecure execution of scripts from network sources",
                                        line_number=line_number + 1,
                                        filepath=file_path,
                                        snippet=file_lines[line_number].strip(),
                                        recommendation="Avoid piping network content directly to a shell. Download, verify checksum/signature, then execute."
                                    ))
        
        return findings
    
    def _scan_jenkins_pipeline(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan Jenkins pipelines for insecure system configuration issues.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Jenkins pipeline checks are more pattern-based since Jenkinsfiles are often represented
        # differently when parsed as YAML
        
        # Check for missing timeout
        has_timeout = False
        for i, line in enumerate(file_lines):
            if "timeout(" in line:
                has_timeout = True
                break
        
        if not has_timeout:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity="MEDIUM",
                description="Missing timeout configuration in Jenkins pipeline",
                line_number=1,
                filepath=file_path,
                snippet=file_lines[0].strip(),
                recommendation="Add timeout { time: X, unit: 'MINUTES' } to prevent runaway jobs"
            ))
        
        # Check for agent configuration without specific version
        agent_line = -1
        for i, line in enumerate(file_lines):
            if "agent {" in line or "agent " in line:
                agent_line = i
                break
        
        if agent_line >= 0:
            # Check next few lines for version specification
            has_version = False
            for i in range(agent_line, min(agent_line + 10, len(file_lines))):
                if "label" in file_lines[i] and "'" in file_lines[i]:
                    has_version = True
                    break
            
            if not has_version:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity="MEDIUM",
                    description="Jenkins agent not pinned to a specific version or label",
                    line_number=agent_line + 1,
                    filepath=file_path,
                    snippet=file_lines[agent_line].strip(),
                    recommendation="Specify a version or label for agents to ensure consistent execution environment"
                ))
        
        # Check for unsafe script execution
        for i, line in enumerate(file_lines):
            if "sh" in line or "powershell" in line or "bat" in line:
                cmd_line = file_lines[i].lower()
                if (("curl" in cmd_line or "wget" in cmd_line) and 
                    ("sh -" in cmd_line or "bash -" in cmd_line or "| sh" in cmd_line or "| bash" in cmd_line)):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.get_severity(),
                        description="Insecure execution of scripts from network sources",
                        line_number=i + 1,
                        filepath=file_path,
                        snippet=file_lines[i].strip(),
                        recommendation="Avoid piping network content directly to a shell. Download, verify checksum/signature, then execute."
                    ))
        
        # Check for missing input validation
        has_input = False
        has_validation = False
        
        for i, line in enumerate(file_lines):
            if "input {" in line:
                has_input = True
                # Check for validation within next 5 lines
                for j in range(i, min(i + 5, len(file_lines))):
                    if "validation {" in file_lines[j]:
                        has_validation = True
                        break
        
        if has_input and not has_validation:
            for i, line in enumerate(file_lines):
                if "input {" in line:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity="MEDIUM",
                        description="Input step missing validation",
                        line_number=i + 1,
                        filepath=file_path,
                        snippet=file_lines[i].strip(),
                        recommendation="Add validation to input steps to prevent invalid or dangerous inputs"
                    ))
                    break
        
        return findings
    
    def _scan_generic_pipeline(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Generic checks for pipeline types that aren't specifically recognized.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Look for unsafe script execution patterns in any pipeline
        unsafe_script_patterns = [
            (r"curl\s+.*\s*\|\s*sh", "curl piped to shell"),
            (r"wget\s+.*\s*\|\s*bash", "wget piped to bash"),
            (r"curl\s+.*\s*\|\s*sudo", "curl piped to sudo"),
            (r"wget\s+.*\s*\|\s*sudo", "wget piped to sudo")
        ]
        
        for pattern, description in unsafe_script_patterns:
            for i, line in enumerate(file_lines):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.get_severity(),
                        description=f"Insecure execution of scripts from network: {description}",
                        line_number=i + 1,
                        filepath=file_path,
                        snippet=line.strip(),
                        recommendation="Avoid piping network content directly to a shell. Download, verify checksum/signature, then execute."
                    ))
        
        # Check for potential insecure temporary file usage
        temp_file_patterns = [
            (r"/tmp/.*\.sh", "Executing scripts from /tmp directory"),
            (r"mktemp.*\.sh", "Executing from mktemp directory without proper validation")
        ]
        
        for pattern, description in temp_file_patterns:
            for i, line in enumerate(file_lines):
                if re.search(pattern, line, re.IGNORECASE) and ("chmod" in line or "bash" in line or "sh" in line):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity="MEDIUM",
                        description=f"Potentially insecure temporary file usage: {description}",
                        line_number=i + 1,
                        filepath=file_path,
                        snippet=line.strip(),
                        recommendation="Avoid executing scripts from world-writable directories or ensure proper file permissions"
                    ))
        
        return findings
    
    def _is_test_or_scan_job(self, job_name: str, job_data: Dict[str, Any]) -> bool:
        """
        Check if a job is a test or scan job.
        
        Args:
            job_name: Name of the job
            job_data: Job configuration
            
        Returns:
            True if job is a test or scan job, False otherwise
        """
        job_name_lower = job_name.lower()
        test_keywords = ["test", "lint", "scan", "check", "verify", "validate"]
        
        # Check job name
        if any(keyword in job_name_lower for keyword in test_keywords):
            return True
            
        # Check step names if available
        if "steps" in job_data and isinstance(job_data["steps"], list):
            step_names = []
            for step in job_data["steps"]:
                if isinstance(step, dict) and "name" in step:
                    step_names.append(step["name"].lower())
            
            # If most steps contain test keywords, consider this a test job
            test_step_count = sum(1 for name in step_names if any(keyword in name for keyword in test_keywords))
            if test_step_count > 0 and test_step_count >= len(step_names) / 2:
                return True
        
        return False
    
    def _find_step_line_number(self, file_lines: List[str], job_name: str, step_index: int) -> int:
        """
        Find the line number for a specific step in a job.
        
        Args:
            file_lines: The file lines
            job_name: Name of the job
            step_index: Index of the step in the job
            
        Returns:
            Line number if found, -1 otherwise
        """
        job_line = -1
        steps_line = -1
        step_count = -1
        
        # Find job line
        for i, line in enumerate(file_lines):
            if line.strip().startswith(f"{job_name}:"):
                job_line = i
                break
                
        if job_line < 0:
            return -1
            
        # Find steps line
        for i in range(job_line, len(file_lines)):
            if "steps:" in file_lines[i]:
                steps_line = i
                break
                
        if steps_line < 0:
            return -1
            
        # Count steps until we reach step_index
        for i in range(steps_line + 1, len(file_lines)):
            if file_lines[i].strip().startswith("- "):
                step_count += 1
                if step_count == step_index:
                    return i
                    
        return -1
    
    def _find_job_services_line(self, file_lines: List[str], job_name: str, service_index: int) -> int:
        """
        Find the line number for a specific service in a job.
        
        Args:
            file_lines: The file lines
            job_name: Name of the job
            service_index: Index of the service in the job
            
        Returns:
            Line number if found, -1 otherwise
        """
        job_line = -1
        services_line = -1
        service_count = -1
        
        # Find job line
        for i, line in enumerate(file_lines):
            if line.strip().startswith(f"{job_name}:"):
                job_line = i
                break
                
        if job_line < 0:
            return -1
            
        # Find services line
        for i in range(job_line, len(file_lines)):
            if "services:" in file_lines[i]:
                services_line = i
                break
                
        if services_line < 0:
            return -1
            
        # Count services until we reach service_index
        for i in range(services_line + 1, len(file_lines)):
            if file_lines[i].strip().startswith("- "):
                service_count += 1
                if service_count == service_index:
                    return i
                    
        return -1
    
    def _find_script_line(self, file_lines: List[str], job_name: str, script_content: str) -> int:
        """
        Find the line number for a specific script content in a job.
        
        Args:
            file_lines: The file lines
            job_name: Name of the job
            script_content: Content of the script to find
            
        Returns:
            Line number if found, -1 otherwise
        """
        job_line = -1
        script_line = -1
        
        # Find job line
        for i, line in enumerate(file_lines):
            if line.strip().startswith(f"{job_name}:"):
                job_line = i
                break
                
        if job_line < 0:
            return -1
            
        # Find script line
        for i in range(job_line, len(file_lines)):
            if "script:" in file_lines[i]:
                script_line = i
                break
                
        if script_line < 0:
            return -1
            
        # Find the specific script content
        for i in range(script_line + 1, len(file_lines)):
            if script_content in file_lines[i]:
                return i
            
            # Stop if we've likely moved past the script section
            if file_lines[i].strip() and not file_lines[i].strip().startswith("-") and not file_lines[i].strip().startswith(" "):
                break
                
        return -1
    
    def _find_azure_task_line(self, file_lines: List[str], job_index: int, step_index: int) -> int:
        """
        Find the line number for a specific task in an Azure DevOps pipeline.
        
        Args:
            file_lines: The file lines
            job_index: Index of the job
            step_index: Index of the step/task within the job
            
        Returns:
            Line number if found, -1 otherwise
        """
        job_count = -1
        job_line = -1
        step_count = -1
        
        # Find job line
        for i, line in enumerate(file_lines):
            if "- job:" in line:
                job_count += 1
                if job_count == job_index:
                    job_line = i
                    break
                    
        if job_line < 0:
            return -1
            
        # Find steps line
        steps_line = -1
        for i in range(job_line, len(file_lines)):
            if "steps:" in file_lines[i]:
                steps_line = i
                break
                
        if steps_line < 0:
            return -1
            
        # Find specific step
        for i in range(steps_line + 1, len(file_lines)):
            if "- task:" in file_lines[i]:
                step_count += 1
                if step_count == step_index:
                    return i
                    
            # Stop if we've moved past the steps section
            if line.strip() and not line.strip().startswith("-") and not line.strip().startswith(" "):
                break
                
        return -1
    
    def _find_line_with_content(self, file_lines: List[str], content: str, start_line: int) -> int:
        """
        Find a line containing specific content.
        
        Args:
            file_lines: The file lines
            content: Content to look for
            start_line: Line to start searching from
            
        Returns:
            Line index if found, -1 otherwise
        """
        for i in range(start_line, len(file_lines)):
            if content in file_lines[i]:
                return i
        return -1
