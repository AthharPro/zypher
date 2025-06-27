import re
from typing import List, Dict, Any, Optional

from .base_rule import BaseRule, Finding


class RuleInsufficientFlowControl(BaseRule):
    """
    Rule to detect insufficient flow control mechanisms in CI/CD pipelines.
    
    This rule identifies:
    1. Missing branch protection patterns
    2. Workflows that can be executed by external contributors without review
    3. Missing approval requirements for sensitive environments
    4. Lack of environment segregation or promotion controls
    """
    
    def __init__(self):
        super().__init__()
    
    def get_severity(self):
        """Return the severity of this rule"""
        return "HIGH"
        
    def scan(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan pipeline data for insufficient flow control mechanisms.
        
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
        Scan GitHub Actions workflows for insufficient flow control mechanisms.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for workflows with direct push access to main or master branch
        if "on" in pipeline_data:
            events = pipeline_data["on"]
            
            if isinstance(events, dict) and "push" in events:
                push_config = events["push"]
                
                # Check if pushing to main or master is allowed
                if push_config and isinstance(push_config, dict) and "branches" in push_config:
                    branches = push_config["branches"]
                    if isinstance(branches, list) and any(b in ["main", "master"] for b in branches):
                        line_number = self._find_line_with_content(file_lines, "push:", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=self.get_severity(),
                                description="Direct push to main/master branch without requiring pull requests",
                                line_number=line_number + 1,  # 1-based indexing
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Configure branch protection rules requiring pull request reviews and remove direct push trigger"
                            ))
            
            # Check if workflow can be triggered by pull_request without filtering
            if isinstance(events, dict) and "pull_request" in events:
                pr_config = events["pull_request"]
                
                # If pull_request allows any branches or has no branch filtering
                if pr_config is None or (isinstance(pr_config, dict) and "branches" not in pr_config):
                    line_number = self._find_line_with_content(file_lines, "pull_request", 0)
                    if line_number >= 0:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.get_severity(),
                            description="Workflow can be triggered by pull requests from any branch without restrictions",
                            line_number=line_number + 1,
                            filepath=file_path,
                            snippet=file_lines[line_number].strip(),
                            recommendation="Add branch filtering to the pull_request trigger to limit execution to specific branches only"
                        ))
            
            # Check if workflow can be triggered by external contributors (workflow_run without filtering)
            if isinstance(events, dict) and "workflow_run" in events:
                workflow_config = events["workflow_run"]
                if workflow_config is None or (isinstance(workflow_config, dict) and "workflows" not in workflow_config):
                    line_number = self._find_line_with_content(file_lines, "workflow_run", 0)
                    if line_number >= 0:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.get_severity(),
                            description="Workflow can be triggered by any workflow run without restrictions",
                            line_number=line_number + 1,
                            filepath=file_path,
                            snippet=file_lines[line_number].strip(),
                            recommendation="Specify exactly which workflows should trigger this workflow and add branch filtering"
                        ))
        
        # Check for deployment jobs without environment protection
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                # Check for deployment job with no environment protection
                if job_name.lower() == "deploy" and isinstance(job_data, dict):
                    # Check if the job has an environment defined
                    if "environment" not in job_data:
                        line_number = self._find_line_with_content(file_lines, f"{job_name}:", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=self.get_severity(),
                                description="Deployment job lacks environment protection",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Add an environment with protection rules to require approvals for deployments"
                            ))
                    
                    # Check for missing required reviewers or approvals
                    if not self._has_required_reviewers(job_data):
                        line_number = self._find_line_with_content(file_lines, f"{job_name}:", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=self.get_severity(),
                                description="Deployment lacks required reviewers or approval gates",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Implement required reviewers and approval process for sensitive deployments"
                            ))
        
        # Check for missing environment protection rules in deployments
        environments_without_protection = self._find_environments_without_protection(pipeline_data, file_lines)
        for env_name, line_number in environments_without_protection:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description=f"Environment '{env_name}' used without protection rules",
                line_number=line_number + 1,
                filepath=file_path,
                snippet=file_lines[line_number].strip(),
                recommendation=f"Configure environment protection rules (approvals, timeouts) for '{env_name}' in repository settings"
            ))

        # Check if the workflow contains actions that require separate jobs with approvals
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if isinstance(job_data, dict) and "steps" in job_data:
                    for step_idx, step in enumerate(job_data["steps"]):
                        if isinstance(step, dict):
                            # Look for deployment or infrastructure steps
                            if self._is_sensitive_action(step):
                                line_number = self._find_step_line_number(file_lines, job_name, step_idx)
                                if line_number >= 0:
                                    findings.append(Finding(
                                        rule_id=self.rule_id,
                                        severity=self.get_severity(),
                                        description="Sensitive action executed without approval flow control",
                                        line_number=line_number + 1,
                                        filepath=file_path,
                                        snippet=file_lines[line_number].strip(),
                                        recommendation="Move sensitive actions to separate deployment jobs with approval requirements"
                                    ))
        
        return findings
    
    def _has_required_reviewers(self, job_data: Dict[str, Any]) -> bool:
        """
        Check if a job has required reviewers or approvals.
        
        Args:
            job_data: Job configuration
            
        Returns:
            True if job has approvals, False otherwise
        """
        if not isinstance(job_data, dict):
            return False
            
        # Check for environment with approvals
        if "environment" in job_data:
            env = job_data["environment"]
            if isinstance(env, dict) and "reviewers" in env:
                return True
                
        return False
    
    def _is_sensitive_action(self, step: Dict[str, Any]) -> bool:
        """
        Check if a workflow step is a sensitive action.
        
        Args:
            step: Workflow step configuration
            
        Returns:
            True if step is a sensitive action, False otherwise
        """
        if not isinstance(step, dict):
            return False
            
        # Check for deployments, infrastructure changes, etc.
        sensitive_keywords = [
            "deploy", "kubernetes", "kubectl", 
            "aws", "azure", "gcp", "terraform",
            "docker push", "release"
        ]
        
        # Check the 'run' command if it exists
        if "run" in step and isinstance(step["run"], str):
            return any(keyword in step["run"].lower() for keyword in sensitive_keywords)
            
        # Check the 'uses' action if it exists
        if "uses" in step and isinstance(step["uses"], str):
            return any(keyword in step["uses"].lower() for keyword in sensitive_keywords)
            
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
    
    def _scan_gitlab_ci(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan GitLab CI/CD pipelines for insufficient flow control mechanisms.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for missing workflow rules
        if "workflow" not in pipeline_data:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Missing workflow rules for controlling when pipelines should run",
                line_number=1,
                filepath=file_path,
                snippet=file_lines[0].strip(),
                recommendation="Add workflow rules to control when pipelines should run. Use 'rules' or 'workflow.rules' to define specific conditions"
            ))
            
        # Check for insufficient environment protection in deployments
        production_jobs = self._find_production_deployments(pipeline_data, file_lines)
        for job_name, line_number in production_jobs:
            # Check if the job has a proper when: manual setting or approval requirement
            if not self._has_manual_approval(pipeline_data, job_name):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.get_severity(),
                    description=f"Production deployment job '{job_name}' lacks manual approval gate",
                    line_number=line_number + 1,
                    filepath=file_path,
                    snippet=file_lines[line_number].strip(),
                    recommendation=f"Add 'when: manual' to job '{job_name}' to require manual approval before execution"
                ))
        
        return findings
    
    def _scan_azure_pipeline(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan Azure DevOps pipelines for insufficient flow control mechanisms.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for missing approval checks in environments
        if "stages" in pipeline_data:
            stages = pipeline_data["stages"]
            for i, stage in enumerate(stages) if isinstance(stages, list) else []:
                if "environment" in stage and self._is_sensitive_environment(stage["environment"]):
                    if not self._has_azure_approval(stage):
                        line_number = self._find_line_with_content(file_lines, f"environment: {stage['environment']}", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=self.get_severity(),
                                description=f"Sensitive environment '{stage['environment']}' used without approval gates",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Configure approval checks in environment settings or add approvals directly in the pipeline"
                            ))
        
        return findings
    
    def _scan_jenkins_pipeline(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan Jenkins pipelines for insufficient flow control mechanisms.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for missing input parameters
        has_parameters = any(line.strip().startswith("parameters {") for line in file_lines)
        if not has_parameters:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Pipeline lacks input parameters for control and documentation",
                line_number=1,
                filepath=file_path,
                snippet=file_lines[0].strip(),
                recommendation="Add parameters section to document and control pipeline execution"
            ))
        
        # Check for missing approval stages in production deployments
        deploy_line = -1
        for i, line in enumerate(file_lines):
            if "deploy" in line.lower() and ("prod" in line.lower() or "production" in line.lower()):
                deploy_line = i
                break
        
        if deploy_line >= 0:
            # Look for input step near the deployment
            has_input = any("input" in file_lines[i].lower() 
                           for i in range(max(0, deploy_line - 10), min(len(file_lines), deploy_line + 10)))
            if not has_input:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.get_severity(),
                    description="Production deployment lacks approval step",
                    line_number=deploy_line + 1,
                    filepath=file_path,
                    snippet=file_lines[deploy_line].strip(),
                    recommendation="Add an input step before production deployment to require manual approval"
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
        
        # Look for deployment keywords without protection mechanisms
        deployment_patterns = [
            (r"deploy\s+to\s+(prod|production)", "Production deployment"),
            (r"(release|publish)\s+to", "Release/publishing process")
        ]
        
        for pattern, context in deployment_patterns:
            for i, line in enumerate(file_lines):
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if there's any indication of approvals or protections nearby
                    has_protection = self._check_for_nearby_protection(file_lines, i)
                    if not has_protection:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.get_severity(),
                            description=f"{context} without flow control protections",
                            line_number=i + 1,
                            filepath=file_path,
                            snippet=line.strip(),
                            recommendation="Add approval gates, manual interventions, or other flow control mechanisms to protect sensitive operations"
                        ))
        
        return findings
    
    def _find_environments_without_protection(self, pipeline_data: Dict[str, Any], file_lines: List[str]) -> List[tuple]:
        """
        Find GitHub Actions environments that appear to lack protection.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            
        Returns:
            List of tuples (environment_name, line_number)
        """
        result = []
        
        # For GitHub Actions, we need to check jobs that use environments
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if isinstance(job_data, dict) and "environment" in job_data:
                    env = job_data["environment"]
                    env_name = env if isinstance(env, str) else env.get("name", "") if isinstance(env, dict) else ""
                    
                    # Check if this looks like a sensitive environment
                    if self._is_sensitive_environment(env_name):
                        # Find the line where this environment is defined
                        line_number = -1
                        for i, line in enumerate(file_lines):
                            if "environment:" in line and env_name in line:
                                line_number = i
                                break
                        
                        # We can't directly know if GitHub environment has protection rules,
                        # but we can check if it specifies protection in the pipeline
                        has_protection = (isinstance(env, dict) and 
                                          ("protection_rules" in env or "approvals" in env))
                        
                        if not has_protection and line_number >= 0:
                            result.append((env_name, line_number))
        
        return result
    
    def _find_production_deployments(self, pipeline_data: Dict[str, Any], file_lines: List[str]) -> List[tuple]:
        """
        Find GitLab CI jobs that appear to be production deployments.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            
        Returns:
            List of tuples (job_name, line_number)
        """
        result = []
        
        # Check all job definitions
        for job_name, job_data in pipeline_data.items():
            if not isinstance(job_data, dict):
                continue
                
            # Skip reserved keywords
            if job_name in ["stages", "variables", "workflow", "default", "include"]:
                continue
            
            # Check if this is a deployment job (based on naming or environment)
            is_deployment = (
                "deploy" in job_name.lower() or
                (isinstance(job_data.get("environment"), dict) and "name" in job_data["environment"]) or
                isinstance(job_data.get("environment"), str)
            )
            
            if is_deployment:
                # Check if it looks like a production deployment
                env_name = ""
                if isinstance(job_data.get("environment"), dict) and "name" in job_data["environment"]:
                    env_name = job_data["environment"]["name"]
                elif isinstance(job_data.get("environment"), str):
                    env_name = job_data["environment"]
                
                is_production = self._is_sensitive_environment(env_name) or self._is_sensitive_environment(job_name)
                
                if is_production:
                    # Find line number
                    line_number = -1
                    for i, line in enumerate(file_lines):
                        if line.strip().startswith(f"{job_name}:"):
                            line_number = i
                            break
                    
                    if line_number >= 0:
                        result.append((job_name, line_number))
        
        return result
    
    def _is_sensitive_environment(self, name: str) -> bool:
        """
        Check if an environment name suggests it's a sensitive environment.
        
        Args:
            name: Environment name
            
        Returns:
            True if it appears to be a sensitive environment, False otherwise
        """
        if not name:
            return False
            
        name = name.lower()
        sensitive_keywords = ["prod", "production", "live", "prd", "release", "public", "customer"]
        
        return any(keyword in name for keyword in sensitive_keywords)
    
    def _has_manual_approval(self, pipeline_data: Dict[str, Any], job_name: str) -> bool:
        """
        Check if a GitLab CI job has manual approval requirement.
        
        Args:
            pipeline_data: The parsed pipeline data
            job_name: Name of the job to check
            
        Returns:
            True if job has manual approval, False otherwise
        """
        job_data = pipeline_data.get(job_name, {})
        if not isinstance(job_data, dict):
            return False
        
        # Check for 'when: manual'
        if job_data.get("when") == "manual":
            return True
            
        # Check for a rule with 'when: manual'
        if isinstance(job_data.get("rules"), list):
            for rule in job_data["rules"]:
                if isinstance(rule, dict) and rule.get("when") == "manual":
                    return True
        
        return False
    
    def _has_azure_approval(self, stage: Dict[str, Any]) -> bool:
        """
        Check if an Azure DevOps pipeline stage has approvals.
        
        Args:
            stage: Stage data
            
        Returns:
            True if stage has approval checks, False otherwise
        """
        # Check for approvals in the environment deployment strategy
        if isinstance(stage.get("jobs"), list):
            for job in stage["jobs"]:
                if isinstance(job, dict) and isinstance(job.get("deployment"), dict):
                    strategy = job.get("deployment", {}).get("strategy", {})
                    if isinstance(strategy, dict) and strategy.get("approvals"):
                        return True
        
        return False
    
    def _check_for_nearby_protection(self, file_lines: List[str], line_index: int) -> bool:
        """
        Check if there appear to be protection mechanisms near a given line.
        
        Args:
            file_lines: The raw file lines
            line_index: Index of line to check around
            
        Returns:
            True if protection mechanisms found, False otherwise
        """
        # Define a window to check around the line
        start = max(0, line_index - 10)
        end = min(len(file_lines), line_index + 10)
        
        protection_keywords = [
            "approv", "manual", "when: manual", "input", "require", "confirm", 
            "protected", "permission", "authori", "valid"
        ]
        
        # Check for protection keywords in nearby lines
        return any(
            any(keyword in line.lower() for keyword in protection_keywords)
            for line in file_lines[start:end]
        )
    
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
