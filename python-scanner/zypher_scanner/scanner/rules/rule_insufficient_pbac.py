import re
from typing import List, Dict, Any, Optional

from .base_rule import BaseRule, Finding


class RuleInsufficientPBAC(BaseRule):
    """
    Rule to detect insufficient Pipeline-Based Access Controls (PBAC) in CI/CD pipelines.
    
    This rule identifies:
    1. Missing job-level permission restrictions in GitHub Actions
    2. Excessive permissions for pipeline stages
    3. Lack of separation between build and deployment jobs
    4. Insufficient isolation between environments
    5. Missing pipeline-specific access controls
    """
    
    def __init__(self):
        super().__init__()
    
    def get_severity(self):
        """Return the severity of this rule"""
        return "MEDIUM"
        
    def scan(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan pipeline data for insufficient PBAC issues.
        
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
        Scan GitHub Actions workflows for insufficient PBAC.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for workflow-level permissions
        has_workflow_permissions = "permissions" in pipeline_data
        
        # If no workflow-level permissions, check if all jobs have job-level permissions
        if not has_workflow_permissions:
            if "jobs" in pipeline_data:
                for job_name, job_data in pipeline_data["jobs"].items():
                    if isinstance(job_data, dict) and "permissions" not in job_data:
                        # Find line number for the job
                        line_number = self._find_line_with_content(file_lines, f"{job_name}:", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=self.get_severity(),
                                description=f"Job '{job_name}' lacks explicit permission restrictions",
                                line_number=line_number + 1,  # 1-based indexing
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Add explicit 'permissions' at workflow level or job level to implement principle of least privilege"
                            ))
        
        # Check for jobs with sensitive operations that have write-all permissions
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if not isinstance(job_data, dict):
                    continue
                
                # Check if this job has permissions set
                job_permissions = job_data.get("permissions", {})
                
                # Check if job has too permissive permissions
                if job_permissions == "write-all" or job_permissions == {} or job_permissions is None:
                    # Check if job contains sensitive operations
                    if self._has_sensitive_operations(job_data):
                        line_number = self._find_line_with_content(file_lines, f"{job_name}:", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=self.get_severity(),
                                description=f"Job '{job_name}' with sensitive operations has excessive or default permissions",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Limit job permissions to only those required using explicit permission declarations"
                            ))
        
        # Check for missing OIDC trust conditions when using cloud providers
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if isinstance(job_data, dict) and "steps" in job_data:
                    # Check for cloud provider authentication steps
                    for i, step in enumerate(job_data["steps"]):
                        if isinstance(step, dict) and "uses" in step:
                            action = step["uses"]
                            if self._is_cloud_auth_action(action) and not self._has_oidc_conditions(step):
                                line_number = self._find_step_line(file_lines, job_name, i)
                                if line_number >= 0:
                                    findings.append(Finding(
                                        rule_id=self.rule_id,
                                        severity=self.get_severity(),
                                        description=f"Cloud provider authentication without OIDC trust conditions",
                                        line_number=line_number + 1,
                                        filepath=file_path,
                                        snippet=file_lines[line_number].strip(),
                                        recommendation="Add OIDC trust conditions (e.g., audience, subject claims) to restrict token use"
                                    ))
        
        # Check for mixed build and deployment in the same job
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if isinstance(job_data, dict) and "steps" in job_data:
                    has_build = False
                    has_deploy = False
                    
                    for step in job_data["steps"]:
                        if isinstance(step, dict):
                            step_name = step.get("name", "").lower()
                            step_run = step.get("run", "").lower() if isinstance(step.get("run"), str) else ""
                            step_uses = step.get("uses", "").lower() if isinstance(step.get("uses"), str) else ""
                            
                            # Check for build operations
                            if any(kw in step_name or kw in step_run or kw in step_uses 
                                  for kw in ["build", "compile", "test", "lint"]):
                                has_build = True
                                
                            # Check for deployment operations
                            if any(kw in step_name or kw in step_run or kw in step_uses 
                                  for kw in ["deploy", "publish", "release", "kubectl", "helm"]):
                                has_deploy = True
                    
                    if has_build and has_deploy:
                        line_number = self._find_line_with_content(file_lines, f"{job_name}:", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=self.get_severity(),
                                description=f"Job '{job_name}' mixes build and deployment operations without separation",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Separate build and deployment into different jobs with appropriate permissions and dependencies"
                            ))
        
        return findings
    
    def _scan_gitlab_ci(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan GitLab CI/CD pipelines for insufficient PBAC.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for missing resource access controls
        has_resource_access = False
        for key, value in pipeline_data.items():
            if isinstance(value, dict) and "resource_group" in value:
                has_resource_access = True
                break
        
        # If no resource group constraints found, flag it
        if not has_resource_access and len(pipeline_data) > 2:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Pipeline lacks resource access controls between jobs",
                line_number=1,
                filepath=file_path,
                snippet=file_lines[0].strip() if file_lines else "",
                recommendation="Use 'resource_group' to limit concurrent access to resources between jobs"
            ))
        
        # Check for missing job access controls
        for job_name, job_data in pipeline_data.items():
            # Skip non-job entries
            if not isinstance(job_data, dict) or job_name in ["stages", "variables", "workflow", "default", "include"]:
                continue
                
            # Check if job has rules to restrict when it runs
            has_rules = "rules" in job_data
            has_only = "only" in job_data
            has_except = "except" in job_data
            
            if not (has_rules or has_only or has_except) and self._is_sensitive_job(job_name, job_data):
                line_number = self._find_line_with_content(file_lines, f"{job_name}:", 0)
                if line_number >= 0:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.get_severity(),
                        description=f"Sensitive job '{job_name}' lacks access control rules",
                        line_number=line_number + 1,
                        filepath=file_path,
                        snippet=file_lines[line_number].strip(),
                        recommendation="Add 'rules', 'only', or 'except' conditions to restrict when this job can run"
                    ))
        
        return findings
    
    def _scan_azure_pipeline(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan Azure DevOps pipelines for insufficient PBAC.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for missing service connection restrictions
        if "resources" not in pipeline_data and "stages" in pipeline_data:
            for i, stage in enumerate(pipeline_data["stages"]) if isinstance(pipeline_data["stages"], list) else []:
                if isinstance(stage, dict) and "jobs" in stage:
                    for j, job in enumerate(stage["jobs"]) if isinstance(stage["jobs"], list) else []:
                        # Look for service connection usage without restrictions
                        if isinstance(job, dict) and self._uses_service_connection(job) and not self._has_service_connection_restriction(job):
                            line_number = self._find_stage_job_line(file_lines, i, j)
                            if line_number >= 0:
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    severity=self.get_severity(),
                                    description="Service connection used without access restrictions",
                                    line_number=line_number + 1,
                                    filepath=file_path,
                                    snippet=file_lines[line_number].strip(),
                                    recommendation="Implement service connection restrictions using 'serviceEndpoints' in pipeline resources"
                                ))
        
        # Check for mixed build and release stages
        if "stages" in pipeline_data and isinstance(pipeline_data["stages"], list):
            build_stages = []
            release_stages = []
            
            for i, stage in enumerate(pipeline_data["stages"]):
                if isinstance(stage, dict):
                    stage_name = stage.get("displayName", "").lower() if isinstance(stage.get("displayName"), str) else ""
                    
                    if any(kw in stage_name for kw in ["build", "compile", "test"]):
                        build_stages.append(stage)
                    
                    if any(kw in stage_name for kw in ["deploy", "release", "publish", "production"]):
                        release_stages.append(stage)
                        
                        # Check if release stage has proper approval gates
                        if not self._has_approval_gates(stage):
                            line_number = self._find_stage_line(file_lines, i)
                            if line_number >= 0:
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    severity=self.get_severity(),
                                    description=f"Release stage '{stage_name}' lacks approval gates",
                                    line_number=line_number + 1,
                                    filepath=file_path,
                                    snippet=file_lines[line_number].strip(),
                                    recommendation="Add approval gates with 'approvals' section in environment deployment strategy"
                                ))
            
            # If no separation between build and release, flag it
            if len(build_stages) > 0 and len(release_stages) == 0:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.get_severity(),
                    description="Pipeline lacks separation between build and release stages",
                    line_number=1,
                    filepath=file_path,
                    snippet=file_lines[0].strip() if file_lines else "",
                    recommendation="Separate build and deployment into different stages with appropriate gates and conditions"
                ))
        
        return findings
    
    def _scan_jenkins_pipeline(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan Jenkins pipelines for insufficient PBAC.
        
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
        
        # Check for missing options with job restrictions
        has_options = False
        has_authentication = False
        
        for i, line in enumerate(file_lines):
            if "options {" in line:
                has_options = True
            if "authentication" in line.lower() or "authorization" in line.lower():
                has_authentication = True
        
        if not has_options or not has_authentication:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Jenkins pipeline lacks explicit authorization controls",
                line_number=1,
                filepath=file_path,
                snippet=file_lines[0].strip() if file_lines else "",
                recommendation="Add 'options' block with authorization/authentication settings to restrict access"
            ))
        
        # Look for use of sensitive credentials without restrictions
        for i, line in enumerate(file_lines):
            if "withCredentials" in line and i < len(file_lines) - 1:
                next_lines = " ".join(file_lines[i:min(i+5, len(file_lines))]).lower()
                
                # Check if these credentials are used in a deployment context without stages
                if "deploy" in next_lines or "kubectl" in next_lines or "ssh" in next_lines:
                    # Check if not inside a stage or node with restrictions
                    if "stage(" not in next_lines and "node(" not in next_lines:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.get_severity(),
                            description="Sensitive credentials used without proper pipeline stage isolation",
                            line_number=i + 1,
                            filepath=file_path,
                            snippet=line.strip(),
                            recommendation="Use separate, restricted stages for operations requiring sensitive credentials"
                        ))
        
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
        
        # Look for sensitive operations without apparent access controls
        sensitive_operation_patterns = [
            (r"(kubectl|helm)\s+(apply|install|upgrade|delete)", "Kubernetes operation"),
            (r"ssh\s+[^@]+@[^.]+\.[^.]+", "SSH to remote server"),
            (r"docker\s+(push|login)", "Docker registry operation"),
            (r"aws\s+[a-z0-9-]+\s+(create|delete|update)", "AWS resource modification"),
            (r"az\s+[a-z0-9-]+\s+(create|delete|update)", "Azure resource modification"),
            (r"gcloud\s+[a-z0-9-]+\s+(create|delete|update)", "Google Cloud resource modification")
        ]
        
        for pattern, operation_type in sensitive_operation_patterns:
            for i, line in enumerate(file_lines):
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if we can find access control mechanisms within 10 lines
                    has_access_control = self._find_access_control_indicators(file_lines, i)
                    if not has_access_control:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.get_severity(),
                            description=f"{operation_type} without apparent access controls",
                            line_number=i + 1,
                            filepath=file_path,
                            snippet=line.strip(),
                            recommendation="Implement proper access controls like role restrictions, approvals, or separate restricted jobs"
                        ))
        
        return findings
    
    def _has_sensitive_operations(self, job_data: Dict[str, Any]) -> bool:
        """
        Check if a job contains sensitive operations.
        
        Args:
            job_data: Job configuration
            
        Returns:
            True if job contains sensitive operations, False otherwise
        """
        if not isinstance(job_data, dict) or "steps" not in job_data:
            return False
            
        sensitive_keywords = [
            "deploy", "release", "publish", "kubectl", "helm", "terraform",
            "aws", "azure", "gcloud", "ssh", "scp", "rsync",
            "docker push", "npm publish", "pypi", "secret", "token"
        ]
        
        for step in job_data["steps"]:
            if not isinstance(step, dict):
                continue
                
            # Check step name
            step_name = step.get("name", "").lower() if isinstance(step.get("name"), str) else ""
            if any(kw in step_name for kw in sensitive_keywords):
                return True
                
            # Check run command
            step_run = step.get("run", "").lower() if isinstance(step.get("run"), str) else ""
            if any(kw in step_run for kw in sensitive_keywords):
                return True
                
            # Check uses
            step_uses = step.get("uses", "").lower() if isinstance(step.get("uses"), str) else ""
            if any(kw in step_uses for kw in sensitive_keywords):
                return True
                
        return False
    
    def _is_cloud_auth_action(self, action: str) -> bool:
        """
        Check if an action is for cloud provider authentication.
        
        Args:
            action: GitHub action string
            
        Returns:
            True if action is for cloud authentication, False otherwise
        """
        if not isinstance(action, str):
            return False
            
        cloud_auth_actions = [
            "aws-actions/configure-aws-credentials",
            "azure/login", 
            "google-github-actions/auth",
            "aliyun/acr-login",
            "digitalocean/action-doctl"
        ]
        
        return any(auth_action in action for auth_action in cloud_auth_actions)
    
    def _has_oidc_conditions(self, step: Dict[str, Any]) -> bool:
        """
        Check if a step has OIDC trust conditions.
        
        Args:
            step: Step configuration
            
        Returns:
            True if step has OIDC conditions, False otherwise
        """
        if not isinstance(step, dict) or "with" not in step:
            return False
            
        with_block = step["with"]
        if not isinstance(with_block, dict):
            return False
            
        # Look for OIDC trust conditions
        oidc_keys = ["audience", "role-to-assume", "subject", "sub", "token_audience"]
        
        return any(key in with_block for key in oidc_keys)
    
    def _is_sensitive_job(self, job_name: str, job_data: Dict[str, Any]) -> bool:
        """
        Check if a job is sensitive based on name and script contents.
        
        Args:
            job_name: Name of the job
            job_data: Job configuration
            
        Returns:
            True if job is sensitive, False otherwise
        """
        if not isinstance(job_name, str) or not isinstance(job_data, dict):
            return False
            
        sensitive_job_keywords = ["deploy", "release", "publish", "prod", "production"]
        
        # Check job name
        if any(kw in job_name.lower() for kw in sensitive_job_keywords):
            return True
            
        # Check script contents if available
        script = job_data.get("script", "")
        if isinstance(script, str):
            if any(kw in script.lower() for kw in sensitive_job_keywords):
                return True
                
        # Check if job deals with production environment
        env = job_data.get("environment", "")
        if isinstance(env, str) and any(kw in env.lower() for kw in ["prod", "production", "live"]):
            return True
            
        return False
    
    def _uses_service_connection(self, job_data: Dict[str, Any]) -> bool:
        """
        Check if an Azure DevOps job uses a service connection.
        
        Args:
            job_data: Job configuration
            
        Returns:
            True if job uses a service connection, False otherwise
        """
        if not isinstance(job_data, dict):
            return False
            
        # Check for common service connection usages
        if "task" in job_data:
            if isinstance(job_data["task"], str) and any(kw in job_data["task"].lower() 
                                                      for kw in ["azure", "aws", "kubernetes"]):
                return True
                
        # Check for task inputs
        if "inputs" in job_data and isinstance(job_data["inputs"], dict):
            inputs = job_data["inputs"]
            connection_keys = ["azureSubscription", "awsConnection", "kubernetesServiceConnection", 
                               "serviceConnection", "dockerRegistryServiceConnection"]
            
            return any(key in inputs for key in connection_keys)
            
        return False
    
    def _has_service_connection_restriction(self, job_data: Dict[str, Any]) -> bool:
        """
        Check if there are service connection restrictions.
        
        Args:
            job_data: Job configuration
            
        Returns:
            True if there are restrictions, False otherwise
        """
        return "endpoint" in job_data or "serviceEndpoint" in job_data
    
    def _has_approval_gates(self, stage: Dict[str, Any]) -> bool:
        """
        Check if an Azure DevOps stage has approval gates.
        
        Args:
            stage: Stage configuration
            
        Returns:
            True if stage has approval gates, False otherwise
        """
        if not isinstance(stage, dict):
            return False
            
        # Check for approvals in conditions
        if "condition" in stage and "approval" in str(stage["condition"]).lower():
            return True
            
        # Check for deployment with approvals
        if "jobs" in stage and isinstance(stage["jobs"], list):
            for job in stage["jobs"]:
                if isinstance(job, dict) and "deployment" in job:
                    deployment = job["deployment"]
                    if isinstance(deployment, dict) and "environment" in deployment:
                        env = deployment["environment"]
                        if isinstance(env, dict) and "approval" in str(env).lower():
                            return True
            
        return False
    
    def _find_stage_job_line(self, file_lines: List[str], stage_idx: int, job_idx: int) -> int:
        """
        Find the line number for a specific job in a stage.
        
        Args:
            file_lines: The file lines
            stage_idx: Index of the stage
            job_idx: Index of the job within the stage
            
        Returns:
            Line number if found, -1 otherwise
        """
        stage_marker_count = -1
        job_marker_count = -1
        
        # Find the right stage
        for i, line in enumerate(file_lines):
            if "stage:" in line or "- stage:" in line:
                stage_marker_count += 1
                if stage_marker_count == stage_idx:
                    # Found the right stage, now find the job
                    for j in range(i, len(file_lines)):
                        if "job:" in file_lines[j] or "- job:" in file_lines[j]:
                            job_marker_count += 1
                            if job_marker_count == job_idx:
                                return j
                            
        return -1
    
    def _find_stage_line(self, file_lines: List[str], stage_idx: int) -> int:
        """
        Find the line number for a specific stage.
        
        Args:
            file_lines: The file lines
            stage_idx: Index of the stage
            
        Returns:
            Line number if found, -1 otherwise
        """
        stage_marker_count = -1
        
        for i, line in enumerate(file_lines):
            if "stage:" in line or "- stage:" in line:
                stage_marker_count += 1
                if stage_marker_count == stage_idx:
                    return i
                    
        return -1
    
    def _find_step_line(self, file_lines: List[str], job_name: str, step_idx: int) -> int:
        """
        Find the line number for a specific step in a job.
        
        Args:
            file_lines: The file lines
            job_name: Name of the job
            step_idx: Index of the step
            
        Returns:
            Line number if found, -1 otherwise
        """
        job_line = -1
        steps_line = -1
        step_count = -1
        
        # Find the job line
        for i, line in enumerate(file_lines):
            if line.strip().startswith(f"{job_name}:"):
                job_line = i
                break
                
        if job_line < 0:
            return -1
            
        # Find the steps section
        for i in range(job_line, len(file_lines)):
            if "steps:" in file_lines[i]:
                steps_line = i
                break
                
        if steps_line < 0:
            return -1
            
        # Find the right step
        for i in range(steps_line + 1, len(file_lines)):
            if line.strip().startswith("- "):
                step_count += 1
                if step_count == step_idx:
                    return i
                    
        return -1
    
    def _find_access_control_indicators(self, file_lines: List[str], line_idx: int) -> bool:
        """
        Find indicators of access controls near a line.
        
        Args:
            file_lines: The file lines
            line_idx: Index of line to check around
            
        Returns:
            True if access control indicators found, False otherwise
        """
        start = max(0, line_idx - 10)
        end = min(len(file_lines), line_idx + 10)
        
        access_control_keywords = [
            "permission", "restrict", "role", "rbac", "auth", "grant", "access",
            "approval", "review", "protect", "limit", "boundary"
        ]
        
        for i in range(start, end):
            if any(kw in file_lines[i].lower() for kw in access_control_keywords):
                return True
                
        return False
    
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
