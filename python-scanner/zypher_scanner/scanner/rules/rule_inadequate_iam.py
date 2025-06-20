from typing import Dict, List, Any
import re

from .base_rule import BaseRule, Finding

class RuleInadequateIam(BaseRule):
    def __init__(self):
        super().__init__()
        
    def scan(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan for inadequate identity and access management practices in CI/CD pipelines.
        
        Args:
            pipeline_data: The parsed YAML pipeline configuration
            file_lines: The raw file content as a list of strings
            file_path: Path to the file being scanned
            
        Returns:
            List of Finding objects for detected vulnerabilities
        """
        findings = []
        
        # Check for GitHub Actions permissions
        if "permissions" not in pipeline_data and "on" in pipeline_data:
            # Missing top-level permissions definition (implies default 'write-all')
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                description="Missing explicit permissions definition in workflow (defaults to write-all)",
                line_number=1,  # Top of file
                filepath=file_path,
                snippet=file_lines[0].strip() if file_lines else "",
                recommendation="Add explicit 'permissions' at the top level of your workflow with least privilege principle"
            ))
        
        # Check for jobs and their permissions
        if "jobs" in pipeline_data:
            for job_name, job_config in pipeline_data["jobs"].items():
                # Check for missing job-level permissions
                if "permissions" not in job_config:
                    # Try to find the line number for this job
                    job_line_num = self._find_job_line(file_lines, job_name)
                    
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        description=f"Job '{job_name}' lacks explicit permissions configuration",
                        line_number=job_line_num,
                        filepath=file_path,
                        snippet=self._get_snippet(file_lines, job_line_num),
                        recommendation="Define minimum required permissions for each job using the 'permissions' keyword"
                    ))
                
                # Check for overly permissive job-level permissions
                if "permissions" in job_config and job_config["permissions"] == "write-all":
                    perm_line_num = self._find_permissions_line(file_lines, job_name)
                    
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        description=f"Job '{job_name}' has overly permissive 'write-all' permissions",
                        line_number=perm_line_num,
                        filepath=file_path,
                        snippet=self._get_snippet(file_lines, perm_line_num),
                        recommendation="Specify only the minimum permissions required for the job"
                    ))
                
                # Check for cloud credentials usage
                self._check_cloud_credentials(job_name, job_config, file_lines, file_path, findings)
        
        return findings
    
    def _check_cloud_credentials(self, job_name: str, job_config: Dict[str, Any], 
                               file_lines: List[str], file_path: str, 
                               findings: List[Finding]) -> None:
        """Check for issues with cloud credential usage"""
        if "steps" not in job_config:
            return
            
        for i, step in enumerate(job_config["steps"]):
            # Check for AWS credential configuration without role assumption
            if "uses" in step and "aws-actions/configure-aws-credentials" in step["uses"]:
                if "with" in step:
                    with_config = step["with"]
                    
                    # Check for missing role-to-assume
                    if "role-to-assume" not in with_config:
                        line_num = self._find_step_line(file_lines, job_name, step)
                        
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            description="AWS credentials configured without role assumption",
                            line_number=line_num,
                            filepath=file_path,
                            snippet=self._get_snippet(file_lines, line_num),
                            recommendation="Use 'role-to-assume' instead of direct access keys for AWS authentication"
                        ))
            
            # Check for direct cloud CLI usage without proper authentication
            if "run" in step and isinstance(step["run"], str):
                command = step["run"].lower()
                
                # Check for AWS CLI commands
                if re.search(r"aws\s+\w+", command) and not self._has_proper_aws_auth(job_config):
                    line_num = self._find_command_line(file_lines, job_name, command)
                    
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        description="AWS CLI usage without proper authentication configuration",
                        line_number=line_num,
                        filepath=file_path,
                        snippet=self._get_snippet(file_lines, line_num),
                        recommendation="Configure OIDC authentication or role assumption before using AWS CLI"
                    ))
                
                # Check for Kubernetes commands without proper authentication
                if re.search(r"kubectl\s+\w+", command) and not self._has_proper_k8s_auth(job_config):
                    line_num = self._find_command_line(file_lines, job_name, command)
                    
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        description="Kubectl usage without proper Kubernetes authentication",
                        line_number=line_num,
                        filepath=file_path,
                        snippet=self._get_snippet(file_lines, line_num),
                        recommendation="Use a proper Kubernetes authentication step before running kubectl commands"
                    ))
    
    def _has_proper_aws_auth(self, job_config: Dict[str, Any]) -> bool:
        """Check if the job has proper AWS authentication configured"""
        if "steps" not in job_config:
            return False
            
        for step in job_config["steps"]:
            # Check for standard AWS authentication actions
            if "uses" in step and any(auth_action in step["uses"] for auth_action in [
                "aws-actions/configure-aws-credentials",
                "aws-actions/login-to-amazon-ecr"
            ]):
                if "with" in step and "role-to-assume" in step["with"]:
                    return True
        
        return False
    
    def _has_proper_k8s_auth(self, job_config: Dict[str, Any]) -> bool:
        """Check if the job has proper Kubernetes authentication configured"""
        if "steps" not in job_config:
            return False
            
        for step in job_config["steps"]:
            # Check for Kubernetes authentication actions
            if "uses" in step and any(auth_action in step["uses"] for auth_action in [
                "azure/k8s-set-context",
                "aws-actions/amazon-eks-kubectl",
                "google-github-actions/auth",
                "google-github-actions/get-gke-credentials"
            ]):
                return True
        
        return False
    
    def _find_job_line(self, file_lines: List[str], job_name: str) -> int:
        """Find the line number for a job definition"""
        for i, line in enumerate(file_lines):
            if line.strip().startswith(job_name + ":"):
                return i + 1
        return 1
    
    def _find_permissions_line(self, file_lines: List[str], job_name: str) -> int:
        """Find the line number for permissions in a job"""
        job_line = 0
        for i, line in enumerate(file_lines):
            if line.strip().startswith(job_name + ":"):
                job_line = i + 1
                break
        
        if job_line > 0:
            for i in range(job_line, min(job_line + 10, len(file_lines))):
                if "permissions:" in file_lines[i]:
                    return i + 1
        
        return job_line
    
    def _find_step_line(self, file_lines: List[str], job_name: str, step: Dict[str, Any]) -> int:
        """Find the line number for a step in a job"""
        # First find the job
        job_line = 0
        for i, line in enumerate(file_lines):
            if line.strip().startswith(job_name + ":"):
                job_line = i + 1
                break
                
        if job_line > 0:
            # Try to find the step by its 'uses' or 'name'
            for i in range(job_line, len(file_lines)):
                if "steps:" in file_lines[i]:
                    steps_line = i + 1
                    
                    # Look for the specific step
                    if "uses" in step:
                        for j in range(steps_line, len(file_lines)):
                            if "uses:" in file_lines[j] and step["uses"] in file_lines[j]:
                                return j + 1
                    elif "name" in step:
                        for j in range(steps_line, len(file_lines)):
                            if "name:" in file_lines[j] and step["name"] in file_lines[j]:
                                return j + 1
        
        return 1
    
    def _find_command_line(self, file_lines: List[str], job_name: str, command: str) -> int:
        """Find the line number for a command in a job"""
        # First find the job
        job_line = 0
        for i, line in enumerate(file_lines):
            if line.strip().startswith(job_name + ":"):
                job_line = i + 1
                break
                
        if job_line > 0:
            # Look for the command within the job
            command_first_word = command.split()[0]
            for i in range(job_line, len(file_lines)):
                if command_first_word in file_lines[i].lower():
                    return i + 1
        
        return 1
    
    def _get_snippet(self, file_lines: List[str], line_num: int) -> str:
        """Get the content of a line"""
        if 1 <= line_num <= len(file_lines):
            return file_lines[line_num - 1].strip()
        return ""
