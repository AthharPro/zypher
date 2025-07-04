import re
from typing import List, Dict, Any

from .base_rule import BaseRule, Finding


class RuleInsufficientLogging(BaseRule):
    """
    Rule to detect insufficient logging and visibility in CI/CD pipelines.
    
    This rule identifies:
    1. Missing logging steps or configurations in pipelines
    2. Absence of audit trail mechanisms
    3. Lack of monitoring and alerting configurations
    4. No error or failure handling steps
    5. Missing notifications for critical pipeline events
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "CICD-VULN-010"
        self.severity = "MEDIUM"  # Explicitly set the severity to match metadata
        
        # Known good logging/monitoring tools and practices by platform
        self.logging_patterns = {
            "github": [
                r"actions/upload-artifact",
                r"actions/download-artifact",
                r"step.+(debug|info|error|warn)",
                r"actions/.*slack",
                r"actions/.*notifications?",
                r"actions/.*status",
                r"actions/github-script.*issue",
                r"actions/.*monitoring",
                r"actions/.*logger",
                r"actions/.*telemetry"
            ],
            "gitlab": [
                r"artifacts",
                r"dependency|needs",
                r"when:\s+on_failure",
                r"allow_failure:\s+true",
                r"after_script",
                r"pages",
                r"slack|telegram|email|notification"
            ],
            "azure": [
                r"task:\s+PublishBuildArtifacts",
                r"task:\s+PublishTestResults",
                r"task:\s+PublishCodeCoverageResults",
                r"continueOnError",
                r"notifications?|webhooks?",
                r"AppInsights|LogAnalytics",
                r"Azure\s+Monitor"
            ],
            "jenkins": [
                r"post\s+{",
                r"archiveArtifacts",
                r"junit|xunit",
                r"notifyEveryUnstableBuild",
                r"emailext|mail",
                r"slackSend",
                r"recordIssues"
            ],
            "general": [
                r"log|logger|logging",
                r"monit(or|oring)",
                r"alert|notification",
                r"report|reporting",
                r"audit|trail",
                r"track|tracking",
                r"error\s+handling",
                r"on_failure|on_error"
            ]
        }
        
    def get_severity(self):
        """Return the severity of this rule"""
        # Use severity from metadata loaded in BaseRule initialization
        if self.severity:
            return self.severity
        return "MEDIUM"
        
    def scan(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan pipeline data for insufficient logging and visibility.
        
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
        
        # Check for required logging and visibility features based on pipeline type
        if pipeline_type == "github":
            findings.extend(self._scan_github_workflow(pipeline_data, file_lines, file_path))
        elif pipeline_type == "gitlab":
            findings.extend(self._scan_gitlab_ci(pipeline_data, file_lines, file_path))
        elif pipeline_type == "azure":
            findings.extend(self._scan_azure_pipeline(pipeline_data, file_lines, file_path))
        elif pipeline_type == "jenkins":
            findings.extend(self._scan_jenkins_pipeline(pipeline_data, file_lines, file_path))
        
        # Generic checks for all pipeline types
        findings.extend(self._scan_generic_pipeline(pipeline_data, file_lines, file_path))
        
        return findings
    
    def _detect_pipeline_type(self, pipeline_data: Dict[str, Any]) -> str:
        """
        Detect the type of CI/CD pipeline configuration.
        
        Args:
            pipeline_data: The parsed pipeline data
            
        Returns:
            String indicating pipeline type ("github", "gitlab", "azure", "jenkins", or "general")
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
            return "general"
    
    def _scan_github_workflow(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan GitHub Actions workflows for insufficient logging and visibility.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for artifact upload/download steps
        has_artifact_uploads = False
        has_notifications = False
        has_error_handling = False
        
        # Check workflow-level settings
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if not isinstance(job_data, dict):
                    continue
                
                # Check for error handling at job level
                if job_data.get("continue-on-error") == True:
                    has_error_handling = True
                
                # Check steps for logging, artifact handling, and notifications
                if "steps" in job_data and isinstance(job_data["steps"], list):
                    for step in job_data["steps"]:
                        if not isinstance(step, dict):
                            continue
                        
                        # Check for artifact uploads
                        if "uses" in step and "actions/upload-artifact" in step["uses"]:
                            has_artifact_uploads = True
                        
                        # Check for notifications/status reporting
                        if "uses" in step and any(re.search(pattern, step["uses"], re.IGNORECASE) 
                                                  for pattern in ["slack", "notification", "status"]):
                            has_notifications = True
                        
                        # Check for error handling in individual steps
                        if step.get("continue-on-error") == True:
                            has_error_handling = True
        
        # Add findings for missing logging features
        workflow_line = self._find_line_with_content(file_lines, "name:", 0)
        
        if not has_artifact_uploads:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Missing artifact uploads for build outputs or logs",
                line_number=workflow_line + 1 if workflow_line >= 0 else 1,
                filepath=file_path,
                snippet=file_lines[workflow_line].strip() if workflow_line >= 0 else "GitHub workflow",
                recommendation="Add steps using actions/upload-artifact to preserve build outputs and logs for troubleshooting"
            ))
        
        if not has_notifications:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="No notification or status reporting mechanisms",
                line_number=workflow_line + 1 if workflow_line >= 0 else 1,
                filepath=file_path,
                snippet=file_lines[workflow_line].strip() if workflow_line >= 0 else "GitHub workflow",
                recommendation="Implement status notifications via Slack, email, or other channels for critical workflow events"
            ))
        
        if not has_error_handling:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Insufficient error handling and failure reporting",
                line_number=workflow_line + 1 if workflow_line >= 0 else 1,
                filepath=file_path,
                snippet=file_lines[workflow_line].strip() if workflow_line >= 0 else "GitHub workflow",
                recommendation="Add continue-on-error for non-critical steps and implement error notification mechanisms"
            ))
        
        return findings
    
    def _scan_gitlab_ci(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan GitLab CI/CD pipelines for insufficient logging and visibility.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for artifact configurations
        has_artifacts = False
        has_notifications = False
        has_error_handling = False
        has_pages = False
        
        for key, value in pipeline_data.items():
            # Skip non-job keys
            if not isinstance(value, dict) or key in ["stages", "variables", "workflow", "default"]:
                continue
            
            # Check for artifacts
            if "artifacts" in value:
                has_artifacts = True
            
            # Check for error handling
            if "allow_failure" in value or "when" in value:
                has_error_handling = True
            
            # Check for pages
            if key == "pages":
                has_pages = True
                
            # Check for notifications via script
            if "script" in value:
                scripts = value["script"]
                if isinstance(scripts, list):
                    for script in scripts:
                        if isinstance(script, str) and any(pattern in script.lower() for pattern in ["slack", "notify", "telegram", "email"]):
                            has_notifications = True
                            break
                elif isinstance(scripts, str) and any(pattern in scripts.lower() for pattern in ["slack", "notify", "telegram", "email"]):
                    has_notifications = True
        
        # Add findings for missing logging features
        pipeline_start_line = 0
        
        if not has_artifacts:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Missing artifact configurations for preserving build outputs or logs",
                line_number=pipeline_start_line + 1,
                filepath=file_path,
                snippet="GitLab CI pipeline",
                recommendation="Add 'artifacts' sections to jobs to preserve important outputs, logs, and test results"
            ))
        
        if not has_notifications:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="No notification mechanisms configured",
                line_number=pipeline_start_line + 1,
                filepath=file_path,
                snippet="GitLab CI pipeline",
                recommendation="Implement notifications via GitLab integrations or scripts for critical pipeline events"
            ))
        
        if not has_error_handling:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Insufficient error handling and failure reporting",
                line_number=pipeline_start_line + 1,
                filepath=file_path,
                snippet="GitLab CI pipeline",
                recommendation="Add 'allow_failure' for non-critical jobs and 'when: on_failure' handlers for error reporting"
            ))
        
        if not has_pages and any("test" in key for key in pipeline_data.keys() if isinstance(key, str)):
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Test jobs without published reports",
                line_number=pipeline_start_line + 1,
                filepath=file_path,
                snippet="GitLab CI pipeline",
                recommendation="Use GitLab Pages to publish test reports and documentation for better visibility"
            ))
        
        return findings
    
    def _scan_azure_pipeline(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan Azure DevOps pipelines for insufficient logging and visibility.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        has_artifact_publishing = False
        has_test_result_publishing = False
        has_error_handling = False
        has_monitoring = False
        
        # Check for jobs and steps
        if "jobs" in pipeline_data and isinstance(pipeline_data["jobs"], list):
            for job in pipeline_data["jobs"]:
                if not isinstance(job, dict):
                    continue
                
                # Check job-level error handling
                if job.get("continueOnError") == True:
                    has_error_handling = True
                
                # Check steps
                if "steps" in job and isinstance(job["steps"], list):
                    for step in job["steps"]:
                        if not isinstance(step, dict):
                            continue
                        
                        # Check for artifact publishing
                        if "task" in step and "PublishBuildArtifacts" in step["task"]:
                            has_artifact_publishing = True
                        
                        # Check for test result publishing
                        if "task" in step and "PublishTestResults" in step["task"]:
                            has_test_result_publishing = True
                        
                        # Check for step-level error handling
                        if step.get("continueOnError") == True:
                            has_error_handling = True
                        
                        # Check for monitoring
                        if "task" in step and any(pattern in step["task"] for pattern in ["AppInsights", "LogAnalytics", "Monitor"]):
                            has_monitoring = True
        
        # Add findings for missing logging features
        pipeline_line = 0
        
        if not has_artifact_publishing:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Missing artifact publishing for build outputs or logs",
                line_number=pipeline_line + 1,
                filepath=file_path,
                snippet="Azure DevOps pipeline",
                recommendation="Add PublishBuildArtifacts tasks to preserve build outputs and logs for troubleshooting"
            ))
        
        if not has_test_result_publishing:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="No test result publishing configured",
                line_number=pipeline_line + 1,
                filepath=file_path,
                snippet="Azure DevOps pipeline",
                recommendation="Add PublishTestResults tasks to capture and publish test execution data"
            ))
        
        if not has_error_handling:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Insufficient error handling and failure reporting",
                line_number=pipeline_line + 1,
                filepath=file_path,
                snippet="Azure DevOps pipeline",
                recommendation="Add continueOnError for non-critical tasks and implement error notification mechanisms"
            ))
        
        if not has_monitoring:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="No integration with monitoring services",
                line_number=pipeline_line + 1,
                filepath=file_path,
                snippet="Azure DevOps pipeline",
                recommendation="Integrate with Azure Monitor, App Insights, or Log Analytics for operational visibility"
            ))
        
        return findings
    
    def _scan_jenkins_pipeline(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan Jenkins pipelines for insufficient logging and visibility.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # For Jenkins, we need to rely more on file content than parsed data
        has_post_section = False
        has_archive_artifacts = False
        has_test_publishing = False
        has_notifications = False
        
        for i, line in enumerate(file_lines):
            line_lower = line.lower()
            
            if "post {" in line_lower:
                has_post_section = True
            
            if "archiveartifacts" in line_lower:
                has_archive_artifacts = True
            
            if any(x in line_lower for x in ["junit", "xunit", "publishhtml"]):
                has_test_publishing = True
            
            if any(x in line_lower for x in ["slacksend", "emailext", "mail", "notification"]):
                has_notifications = True
        
        # Add findings for missing logging features
        if not has_post_section:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Missing post section for handling pipeline completion states",
                line_number=1,
                filepath=file_path,
                snippet="Jenkins pipeline",
                recommendation="Add a post section with success, failure, and always blocks to handle different pipeline states"
            ))
        
        if not has_archive_artifacts:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="No artifact archiving configured",
                line_number=1,
                filepath=file_path,
                snippet="Jenkins pipeline",
                recommendation="Use archiveArtifacts to preserve build outputs, logs, and other artifacts for troubleshooting"
            ))
        
        if not has_test_publishing:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="No test result publishing configured",
                line_number=1,
                filepath=file_path,
                snippet="Jenkins pipeline",
                recommendation="Use junit, xunit, or publishHTML steps to capture and publish test execution data"
            ))
        
        if not has_notifications:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="Missing notification mechanisms",
                line_number=1,
                filepath=file_path,
                snippet="Jenkins pipeline",
                recommendation="Implement notifications via Slack, email, or other channels for critical pipeline events"
            ))
        
        return findings
    
    def _scan_generic_pipeline(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Generic checks for logging and visibility in any pipeline type.
        
        Args:
            pipeline_data: The parsed pipeline data
            file_lines: The raw file lines
            file_path: Path to the pipeline file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check for common logging, monitoring, and notification patterns
        file_content = "\n".join(file_lines).lower()
        
        # Check if any logging patterns are present
        has_logging = any(re.search(pattern, file_content, re.IGNORECASE) for pattern in self.logging_patterns["general"])
        
        # Check if there are any deployment or production steps without accompanying logging
        has_deployments = re.search(r"deploy|production|release|publish", file_content, re.IGNORECASE) is not None
        
        if not has_logging:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description="No logging, monitoring, or notification mechanisms detected",
                line_number=1,
                filepath=file_path,
                snippet="Pipeline configuration",
                recommendation="Implement logging, monitoring, and notification capabilities for operational visibility"
            ))
        elif has_deployments and not has_logging:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity="HIGH",  # Increased severity for deployment without logging
                description="Deployment steps without proper logging or notifications",
                line_number=1,
                filepath=file_path,
                snippet="Pipeline configuration",
                recommendation="Add logging and notification steps specifically for deployment operations"
            ))
        
        # Check for pipeline complexity without corresponding logging
        step_count = 0
        for line in file_lines:
            if line.strip().startswith("- ") or line.strip().startswith("step"):
                step_count += 1
        
        if step_count > 10 and not has_logging:  # Complex pipeline without logging
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.get_severity(),
                description=f"Complex pipeline ({step_count} steps) with insufficient logging",
                line_number=1,
                filepath=file_path,
                snippet="Pipeline configuration",
                recommendation="Add appropriate logging at key points in the pipeline to improve observability"
            ))
        
        return findings
    
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
