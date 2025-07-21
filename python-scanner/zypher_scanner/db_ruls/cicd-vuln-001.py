import re
from typing import List, Dict, Any, Optional

from .base_rules import BaseRule, Finding

class RuleInsufficientFlowControl(BaseRule):
    METADATA = {
        "rule_id": "CICD-VULN-001",
        "rule_name": "Insufficient Flow Control Mechanisms",
        "severity": "HIGH"
    }

    def __init__(self):
        super().__init__()

    def get_severity(self):
        return self.METADATA["severity"]

    def scan(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        findings = []
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
            findings.extend(self._scan_generic_pipeline(pipeline_data, file_lines, file_path))
        return findings

    def _detect_pipeline_type(self, pipeline_data: Dict[str, Any]) -> str:
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

    # --- GitHub Actions ---
    def _scan_github_workflow(self, pipeline_data, file_lines, file_path):
        findings = []
        print("Pipeline Data: ", pipeline_data)  # Debugging line to check pipeline data
        # 1. Direct push to main/master
        if "on" in pipeline_data:
            events = pipeline_data["on"]
            if isinstance(events, dict) and "push" in events:
                push_config = events["push"]
                if push_config and isinstance(push_config, dict) and "branches" in push_config:
                    branches = push_config["branches"]
                    if isinstance(branches, list) and any(b in ["main", "master"] for b in branches):
                        line_number = self._find_line_with_content(file_lines, "push:", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=self.get_severity(),
                                description="Direct push to main/master branch without requiring pull requests",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Configure branch protection rules requiring pull request reviews and remove direct push trigger"
                            ))
            # 2. PR trigger without branch filtering
            if isinstance(events, dict) and "pull_request" in events:
                pr_config = events["pull_request"]
                if pr_config is None or (isinstance(pr_config, dict) and "branches" not in pr_config):
                    line_number = self._find_line_with_content(file_lines, "pull_request", 0)
                    if line_number >= 0:
                        findings.append(Finding(
                            rule_id=self.METADATA["rule_id"],
                            severity=self.get_severity(),
                            description="Workflow can be triggered by pull requests from any branch without restrictions",
                            line_number=line_number + 1,
                            filepath=file_path,
                            snippet=file_lines[line_number].strip(),
                            recommendation="Add branch filtering to the pull_request trigger to limit execution to specific branches only"
                        ))
            # 3. workflow_run without filtering
            if isinstance(events, dict) and "workflow_run" in events:
                workflow_config = events["workflow_run"]
                if workflow_config is None or (isinstance(workflow_config, dict) and "workflows" not in workflow_config):
                    line_number = self._find_line_with_content(file_lines, "workflow_run", 0)
                    if line_number >= 0:
                        findings.append(Finding(
                            rule_id=self.METADATA["rule_id"],
                            severity=self.get_severity(),
                            description="Workflow can be triggered by any workflow run without restrictions",
                            line_number=line_number + 1,
                            filepath=file_path,
                            snippet=file_lines[line_number].strip(),
                            recommendation="Specify exactly which workflows should trigger this workflow and add branch filtering"
                        ))
        # 4. Deployment jobs without environment protection or reviewers
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if job_name.lower() == "deploy" and isinstance(job_data, dict):
                    if "environment" not in job_data:
                        line_number = self._find_line_with_content(file_lines, f"{job_name}:", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=self.get_severity(),
                                description="Deployment job lacks environment protection",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Add an environment with protection rules to require approvals for deployments"
                            ))
                    if not self._has_required_reviewers(job_data):
                        line_number = self._find_line_with_content(file_lines, f"{job_name}:", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=self.get_severity(),
                                description="Deployment lacks required reviewers or approval gates",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Implement required reviewers and approval process for sensitive deployments"
                            ))
        # 5. Environments without protection
        environments_without_protection = self._find_environments_without_protection(pipeline_data, file_lines)
        for env_name, line_number in environments_without_protection:
            findings.append(Finding(
                rule_id=self.METADATA["rule_id"],
                severity=self.get_severity(),
                description=f"Environment '{env_name}' used without protection rules",
                line_number=line_number + 1,
                filepath=file_path,
                snippet=file_lines[line_number].strip(),
                recommendation=f"Configure environment protection rules (approvals, timeouts) for '{env_name}' in repository settings"
            ))
        # 6. Sensitive actions without approval
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if isinstance(job_data, dict) and "steps" in job_data:
                    for step_idx, step in enumerate(job_data["steps"]):
                        if isinstance(step, dict) and self._is_sensitive_action(step):
                            line_number = self._find_step_line_number(file_lines, job_name, step_idx)
                            if line_number >= 0:
                                findings.append(Finding(
                                    rule_id=self.METADATA["rule_id"],
                                    severity=self.get_severity(),
                                    description="Sensitive action executed without approval flow control",
                                    line_number=line_number + 1,
                                    filepath=file_path,
                                    snippet=file_lines[line_number].strip(),
                                    recommendation="Move sensitive actions to separate deployment jobs with approval requirements"
                                ))
        return findings

    def _has_required_reviewers(self, job_data: Dict[str, Any]) -> bool:
        if not isinstance(job_data, dict):
            return False
        if "environment" in job_data:
            env = job_data["environment"]
            if isinstance(env, dict) and "reviewers" in env:
                return True
        return False

    def _is_sensitive_action(self, step: Dict[str, Any]) -> bool:
        sensitive_keywords = [
            "deploy", "kubernetes", "kubectl", 
            "aws", "azure", "gcp", "terraform",
            "docker push", "release"
        ]
        if "run" in step and isinstance(step["run"], str):
            return any(keyword in step["run"].lower() for keyword in sensitive_keywords)
        if "uses" in step and isinstance(step["uses"], str):
            return any(keyword in step["uses"].lower() for keyword in sensitive_keywords)
        return False

    def _find_step_line_number(self, file_lines: List[str], job_name: str, step_index: int) -> int:
        job_line = -1
        steps_line = -1
        step_count = -1
        for i, line in enumerate(file_lines):
            if line.strip().startswith(f"{job_name}:"):
                job_line = i
                break
        if job_line < 0:
            return -1
        for i in range(job_line, len(file_lines)):
            if "steps:" in file_lines[i]:
                steps_line = i
                break
        if steps_line < 0:
            return -1
        for i in range(steps_line + 1, len(file_lines)):
            if file_lines[i].strip().startswith("- "):
                step_count += 1
                if step_count == step_index:
                    return i
        return -1

    # --- GitLab ---
    def _scan_gitlab_ci(self, pipeline_data, file_lines, file_path):
        findings = []
        if "workflow" not in pipeline_data:
            findings.append(Finding(
                rule_id=self.METADATA["rule_id"],
                severity=self.get_severity(),
                description="Missing workflow rules for controlling when pipelines should run",
                line_number=1,
                filepath=file_path,
                snippet=file_lines[0].strip(),
                recommendation="Add workflow rules to control when pipelines should run. Use 'rules' or 'workflow.rules' to define specific conditions"
            ))
        production_jobs = self._find_production_deployments(pipeline_data, file_lines)
        for job_name, line_number in production_jobs:
            if not self._has_manual_approval(pipeline_data, job_name):
                findings.append(Finding(
                    rule_id=self.METADATA["rule_id"],
                    severity=self.get_severity(),
                    description=f"Production deployment job '{job_name}' lacks manual approval gate",
                    line_number=line_number + 1,
                    filepath=file_path,
                    snippet=file_lines[line_number].strip(),
                    recommendation=f"Add 'when: manual' to job '{job_name}' to require manual approval before execution"
                ))
        return findings

    # --- Azure ---
    def _scan_azure_pipeline(self, pipeline_data, file_lines, file_path):
        findings = []
        if "stages" in pipeline_data:
            stages = pipeline_data["stages"]
            for i, stage in enumerate(stages) if isinstance(stages, list) else []:
                if "environment" in stage and self._is_sensitive_environment(stage["environment"]):
                    if not self._has_azure_approval(stage):
                        line_number = self._find_line_with_content(file_lines, f"environment: {stage['environment']}", 0)
                        if line_number >= 0:
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=self.get_severity(),
                                description=f"Sensitive environment '{stage['environment']}' used without approval gates",
                                line_number=line_number + 1,
                                filepath=file_path,
                                snippet=file_lines[line_number].strip(),
                                recommendation="Configure approval checks in environment settings or add approvals directly in the pipeline"
                            ))
        return findings

    # --- Jenkins ---
    def _scan_jenkins_pipeline(self, pipeline_data, file_lines, file_path):
        findings = []
        has_parameters = any(line.strip().startswith("parameters {") for line in file_lines)
        if not has_parameters:
            findings.append(Finding(
                rule_id=self.METADATA["rule_id"],
                severity=self.get_severity(),
                description="Pipeline lacks input parameters for control and documentation",
                line_number=1,
                filepath=file_path,
                snippet=file_lines[0].strip(),
                recommendation="Add parameters section to document and control pipeline execution"
            ))
        deploy_line = -1
        for i, line in enumerate(file_lines):
            if "deploy" in line.lower() and ("prod" in line.lower() or "production" in line.lower()):
                deploy_line = i
                break
        if deploy_line >= 0:
            has_input = any("input" in file_lines[i].lower() 
                           for i in range(max(0, deploy_line - 10), min(len(file_lines), deploy_line + 10)))
            if not has_input:
                findings.append(Finding(
                    rule_id=self.METADATA["rule_id"],
                    severity=self.get_severity(),
                    description="Production deployment lacks approval step",
                    line_number=deploy_line + 1,
                    filepath=file_path,
                    snippet=file_lines[deploy_line].strip(),
                    recommendation="Add an input step before production deployment to require manual approval"
                ))
        return findings

    # --- Generic ---
    def _scan_generic_pipeline(self, pipeline_data, file_lines, file_path):
        findings = []
        deployment_patterns = [
            (r"deploy\s+to\s+(prod|production)", "Production deployment"),
            (r"(release|publish)\s+to", "Release/publishing process")
        ]
        for pattern, context in deployment_patterns:
            for i, line in enumerate(file_lines):
                if re.search(pattern, line, re.IGNORECASE):
                    has_protection = self._check_for_nearby_protection(file_lines, i)
                    if not has_protection:
                        findings.append(Finding(
                            rule_id=self.METADATA["rule_id"],
                            severity=self.get_severity(),
                            description=f"{context} without flow control protections",
                            line_number=i + 1,
                            filepath=file_path,
                            snippet=line.strip(),
                            recommendation="Add approval gates, manual interventions, or other flow control mechanisms to protect sensitive operations"
                        ))
        return findings

    # --- Helpers ---
    def _find_environments_without_protection(self, pipeline_data: Dict[str, Any], file_lines: List[str]) -> List[tuple]:
        result = []
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if isinstance(job_data, dict) and "environment" in job_data:
                    env = job_data["environment"]
                    env_name = env if isinstance(env, str) else env.get("name", "") if isinstance(env, dict) else ""
                    if self._is_sensitive_environment(env_name):
                        line_number = -1
                        for i, line in enumerate(file_lines):
                            if "environment:" in line and env_name in line:
                                line_number = i
                                break
                        has_protection = (isinstance(env, dict) and 
                                          ("protection_rules" in env or "approvals" in env))
                        if not has_protection and line_number >= 0:
                            result.append((env_name, line_number))
        return result

    def _find_production_deployments(self, pipeline_data: Dict[str, Any], file_lines: List[str]) -> List[tuple]:
        result = []
        for job_name, job_data in pipeline_data.items():
            if not isinstance(job_data, dict):
                continue
            if job_name in ["stages", "variables", "workflow", "default", "include"]:
                continue
            is_deployment = (
                "deploy" in job_name.lower() or
                (isinstance(job_data.get("environment"), dict) and "name" in job_data["environment"]) or
                isinstance(job_data.get("environment"), str)
            )
            if is_deployment:
                env_name = ""
                if isinstance(job_data.get("environment"), dict) and "name" in job_data["environment"]:
                    env_name = job_data["environment"]["name"]
                elif isinstance(job_data.get("environment"), str):
                    env_name = job_data["environment"]
                is_production = self._is_sensitive_environment(env_name) or self._is_sensitive_environment(job_name)
                if is_production:
                    line_number = -1
                    for i, line in enumerate(file_lines):
                        if line.strip().startswith(f"{job_name}:"):
                            line_number = i
                            break
                    if line_number >= 0:
                        result.append((job_name, line_number))
        return result

    def _is_sensitive_environment(self, name: str) -> bool:
        if not name:
            return False
        name = name.lower()
        sensitive_keywords = ["prod", "production", "live", "prd", "release", "public", "customer"]
        return any(keyword in name for keyword in sensitive_keywords)

    def _has_manual_approval(self, pipeline_data: Dict[str, Any], job_name: str) -> bool:
        job_data = pipeline_data.get(job_name, {})
        if not isinstance(job_data, dict):
            return False
        if job_data.get("when") == "manual":
            return True
        if isinstance(job_data.get("rules"), list):
            for rule in job_data["rules"]:
                if isinstance(rule, dict) and rule.get("when") == "manual":
                    return True
        return False

    def _has_azure_approval(self, stage: Dict[str, Any]) -> bool:
        if isinstance(stage.get("jobs"), list):
            for job in stage["jobs"]:
                if isinstance(job, dict) and isinstance(job.get("deployment"), dict):
                    strategy = job.get("deployment", {}).get("strategy", {})
                    if isinstance(strategy, dict) and strategy.get("approvals"):
                        return True
        return False

    def _check_for_nearby_protection(self, file_lines: List[str], line_index: int) -> bool:
        start = max(0, line_index - 10)
        end = min(len(file_lines), line_index + 10)
        protection_keywords = [
            "approv", "manual", "when: manual", "input", "require", "confirm", 
            "protected", "permission", "authori", "valid"
        ]
        return any(
            any(keyword in line.lower() for keyword in protection_keywords)
            for line in file_lines[start:end]
        )

    def _find_line_with_content(self, file_lines: List[str], content: str, start_line: int) -> int:
        for i in range(start_line, len(file_lines)):
            if content in file_lines[i]:
                return i
        return -1