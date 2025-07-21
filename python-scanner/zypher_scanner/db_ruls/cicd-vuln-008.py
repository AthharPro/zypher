import re
from typing import List, Dict, Any, Optional
import urllib.parse
from .base_rules import BaseRule, Finding

class RuleUngoverned3rdPartyServices(BaseRule):
    METADATA = {
        "rule_id": "CICD-VULN-008",
        "rule_name": "Ungoverned Usage of 3rd Party Services",
        "severity": "MEDIUM"
    }

    def __init__(self):
        super().__init__()
        self.trusted_maintainers = [
            "actions", "github", "azure", "aws-actions", "hashicorp", 
            "docker", "googlecloudplatform", "azure-pipelines"
        ]
        self.secure_action_patterns = {
            "actions/checkout": "@v3",
            "actions/setup-node": "@v3",
            "actions/setup-python": "@v4",
            "actions/setup-java": "@v3",
            "actions/cache": "@v3"
        }

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
        if "jobs" in pipeline_data:
            for job_name, job_data in pipeline_data["jobs"].items():
                if not isinstance(job_data, dict) or "steps" not in job_data:
                    continue
                steps = job_data["steps"]
                for step_idx, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue
                    if "uses" in step:
                        action_ref = step["uses"]
                        line_number = self._find_step_line_number(file_lines, job_name, step_idx)
                        if self._is_version_tag_only(action_ref):
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=self.get_severity(),
                                description="Action not pinned to a specific commit hash",
                                line_number=line_number + 1 if line_number >= 0 else 1,
                                filepath=file_path,
                                snippet=f"uses: {action_ref}",
                                recommendation="Use commit SHA references instead of version tags for GitHub Actions (e.g., actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675)"
                            ))
                        if self._is_untrusted_action(action_ref):
                            severity = "HIGH" if self._has_elevated_permissions(job_data) else self.get_severity()
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=severity,
                                description=f"Usage of third-party action '{action_ref}' without proper validation",
                                line_number=line_number + 1 if line_number >= 0 else 1,
                                filepath=file_path,
                                snippet=f"uses: {action_ref}",
                                recommendation="Verify third-party actions before use, prefer official actions, and pin to specific commit hashes"
                            ))
                        recommendation = self._check_for_outdated_action(action_ref)
                        if recommendation:
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity="LOW",
                                description=f"Using outdated version of action: {action_ref}",
                                line_number=line_number + 1 if line_number >= 0 else 1,
                                filepath=file_path,
                                snippet=f"uses: {action_ref}",
                                recommendation=recommendation
                            ))
                    if "run" in step and isinstance(step["run"], str):
                        command = step["run"]
                        if self._has_unverified_script_download(command):
                            line_number = self._find_step_line_number(file_lines, job_name, step_idx)
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=self.get_severity(),
                                description="Downloading scripts without integrity verification",
                                line_number=line_number + 1 if line_number >= 0 else 1,
                                filepath=file_path,
                                snippet=command.split("\n")[0] if "\n" in command else command,
                                recommendation="Download scripts to temporary files, verify checksums or signatures, then execute them"
                            ))
        return findings

    # --- GitLab CI ---
    def _scan_gitlab_ci(self, pipeline_data, file_lines, file_path):
        findings = []
        for key, value in pipeline_data.items():
            if not isinstance(value, dict):
                continue
            if key in ["stages", "variables", "workflow", "default", "include"]:
                continue
            if "image" in value:
                image_ref = value["image"]
                image_str = str(image_ref)
                line_number = self._find_line_with_content(file_lines, f"image: {image_str}" if image_str in file_lines else "image:", 0)
                if self._is_latest_or_no_tag(image_str):
                    findings.append(Finding(
                        rule_id=self.METADATA["rule_id"],
                        severity=self.get_severity(),
                        description=f"Using unspecific 'latest' tag or missing tag for Docker image: {image_str}",
                        line_number=line_number + 1 if line_number >= 0 else 1,
                        filepath=file_path,
                        snippet=f"image: {image_str}" if line_number >= 0 else f"image: {image_str}",
                        recommendation="Use specific version tags or digests for Docker images to ensure consistent execution"
                    ))
                if self._is_untrusted_registry(image_str):
                    findings.append(Finding(
                        rule_id=self.METADATA["rule_id"],
                        severity=self.get_severity(),
                        description=f"Using image from potentially untrusted registry: {image_str}",
                        line_number=line_number + 1 if line_number >= 0 else 1,
                        filepath=file_path,
                        snippet=f"image: {image_str}" if line_number >= 0 else f"image: {image_str}",
                        recommendation="Use images from trusted and verified registries, preferably private or official repositories"
                    ))
            if "script" in value:
                scripts = value["script"]
                if isinstance(scripts, list):
                    for script in scripts:
                        if isinstance(script, str) and self._has_unverified_script_download(script):
                            line_number = self._find_line_with_content(file_lines, script[:40], 0)
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=self.get_severity(),
                                description="Downloading scripts without integrity verification",
                                line_number=line_number + 1 if line_number >= 0 else 1,
                                filepath=file_path,
                                snippet=script[:100],
                                recommendation="Download scripts to temporary files, verify checksums or signatures, then execute them"
                            ))
                elif isinstance(scripts, str) and self._has_unverified_script_download(scripts):
                    line_number = self._find_line_with_content(file_lines, scripts[:40], 0)
                    findings.append(Finding(
                        rule_id=self.METADATA["rule_id"],
                        severity=self.get_severity(),
                        description="Downloading scripts without integrity verification",
                        line_number=line_number + 1 if line_number >= 0 else 1,
                        filepath=file_path,
                        snippet=scripts[:100],
                        recommendation="Download scripts to temporary files, verify checksums or signatures, then execute them"
                    ))
            if "services" in value and isinstance(value["services"], list):
                for service_idx, service in enumerate(value["services"]):
                    service_str = str(service)
                    if self._is_latest_or_no_tag(service_str):
                        line_number = self._find_line_with_content(file_lines, service_str, 0)
                        findings.append(Finding(
                            rule_id=self.METADATA["rule_id"],
                            severity=self.get_severity(),
                            description=f"Using unspecific 'latest' tag or missing tag for service: {service_str}",
                            line_number=line_number + 1 if line_number >= 0 else 1,
                            filepath=file_path,
                            snippet=service_str if line_number >= 0 else service_str,
                            recommendation="Use specific version tags or digests for Docker services to ensure consistent execution"
                        ))
        return findings

    # --- Azure DevOps ---
    def _scan_azure_pipeline(self, pipeline_data, file_lines, file_path):
        findings = []
        if "jobs" in pipeline_data:
            for job_idx, job in enumerate(pipeline_data["jobs"] if isinstance(pipeline_data["jobs"], list) else []):
                if not isinstance(job, dict) or "steps" not in job:
                    continue
                for step_idx, step in enumerate(job["steps"] if isinstance(job["steps"], list) else []):
                    if not isinstance(step, dict):
                        continue
                    if "task" in step:
                        task_name = step["task"]
                        line_number = self._find_azure_task_line(file_lines, job_idx, step_idx)
                        if self._is_third_party_azure_task(task_name):
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=self.get_severity(),
                                description=f"Using third-party task '{task_name}' without verification",
                                line_number=line_number + 1 if line_number >= 0 else 1,
                                filepath=file_path,
                                snippet=f"task: {task_name}" if line_number >= 0 else f"task: {task_name}",
                                recommendation="Verify third-party tasks before use, prefer official Microsoft tasks, and pin to specific versions"
                            ))
                        if not self._has_version_pinned(step):
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=self.get_severity(),
                                description=f"Task '{task_name}' not pinned to a specific version",
                                line_number=line_number + 1 if line_number >= 0 else 1,
                                filepath=file_path,
                                snippet=f"task: {task_name}" if line_number >= 0 else f"task: {task_name}",
                                recommendation="Pin tasks to specific versions using the 'version' property"
                            ))
                    if ("powershell" in step or "bash" in step) and "script" in step.get("inputs", {}):
                        script = step["inputs"]["script"]
                        if isinstance(script, str) and self._has_unverified_script_download(script):
                            line_number = self._find_azure_task_line(file_lines, job_idx, step_idx)
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=self.get_severity(),
                                description="Downloading scripts without integrity verification",
                                line_number=line_number + 1 if line_number >= 0 else 1,
                                filepath=file_path,
                                snippet=script[:100],
                                recommendation="Download scripts to temporary files, verify checksums or signatures, then execute them"
                            ))
        if "resources" in pipeline_data:
            resources = pipeline_data["resources"]
            if "repositories" in resources and isinstance(resources["repositories"], list):
                for repo_idx, repo in enumerate(resources["repositories"]):
                    if isinstance(repo, dict) and "ref" not in repo:
                        line_number = self._find_resource_line(file_lines, "repositories", repo_idx)
                        findings.append(Finding(
                            rule_id=self.METADATA["rule_id"],
                            severity=self.get_severity(),
                            description=f"Repository resource '{repo.get('repository', 'unknown')}' not pinned to a specific version",
                            line_number=line_number + 1 if line_number >= 0 else 1,
                            filepath=file_path,
                            snippet=f"- repository: {repo.get('repository', 'unknown')}" if line_number >= 0 else f"Repository: {repo.get('repository', 'unknown')}",
                            recommendation="Pin repository references to specific branches, tags, or commits using the 'ref' property"
                        ))
        return findings

    # --- Jenkins ---
    def _scan_jenkins_pipeline(self, pipeline_data, file_lines, file_path):
        findings = []
        for i, line in enumerate(file_lines):
            if "@Library" in line and ")" in line:
                has_version = "@" in line.split("(")[1].split(")")[0]
                if not has_version:
                    findings.append(Finding(
                        rule_id=self.METADATA["rule_id"],
                        severity=self.get_severity(),
                        description="Shared library used without version pinning",
                        line_number=i + 1,
                        filepath=file_path,
                        snippet=line.strip(),
                        recommendation="Specify a version or tag when importing shared libraries: @Library('my-library@1.0')"
                    ))
            if "sh" in line and ("'" in line or '"' in line):
                shell_cmd = line.split("sh")[1].strip()
                if shell_cmd and (shell_cmd.startswith("'") or shell_cmd.startswith('"')):
                    quote = shell_cmd[0]
                    end_quote_pos = shell_cmd[1:].find(quote) + 1
                    if end_quote_pos > 0:
                        cmd = shell_cmd[1:end_quote_pos]
                        if self._has_unverified_script_download(cmd):
                            findings.append(Finding(
                                rule_id=self.METADATA["rule_id"],
                                severity=self.get_severity(),
                                description="Downloading scripts without integrity verification",
                                line_number=i + 1,
                                filepath=file_path,
                                snippet=line.strip(),
                                recommendation="Download scripts to temporary files, verify checksums or signatures, then execute them"
                            ))
            if ("docker.image" in line or "docker.build" in line) and "'" in line:
                if ":latest" in line or not re.search(r':[^\'"/]+', line):
                    findings.append(Finding(
                        rule_id=self.METADATA["rule_id"],
                        severity=self.get_severity(),
                        description="Docker image used without specific version tag",
                        line_number=i + 1,
                        filepath=file_path,
                        snippet=line.strip(),
                        recommendation="Specify exact version tags for Docker images instead of 'latest' or no tag"
                    ))
        return findings

    # --- Generic ---
    def _scan_generic_pipeline(self, pipeline_data, file_lines, file_path):
        findings = []
        download_patterns = [
            (r"curl\s+(?!.*sha256sum|.*gpg).*https?://", "curl downloading from URL without verification"),
            (r"wget\s+(?!.*sha256sum|.*gpg).*https?://", "wget downloading from URL without verification")
        ]
        for pattern, description in download_patterns:
            for i, line in enumerate(file_lines):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id=self.METADATA["rule_id"],
                        severity=self.get_severity(),
                        description=f"Unverified download: {description}",
                        line_number=i + 1,
                        filepath=file_path,
                        snippet=line.strip(),
                        recommendation="Verify downloaded content with checksums, signatures, or secure hash verification"
                    ))
        docker_patterns = [
            (r"image:\s+['\"]?[\w\.\-\/]+['\"]?$", "Docker image without version tag"),
            (r"image:\s+['\"]?[\w\.\-\/]+:latest['\"]?", "Docker image with 'latest' tag")
        ]
        for pattern, description in docker_patterns:
            for i, line in enumerate(file_lines):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id=self.METADATA["rule_id"],
                        severity=self.get_severity(),
                        description=description,
                        line_number=i + 1,
                        filepath=file_path,
                        snippet=line.strip(),
                        recommendation="Use specific version tags for Docker images to ensure consistent execution"
                    ))
        return findings

    # --- Helper methods below (unchanged from your original code, for brevity) ---
    def _is_version_tag_only(self, action_ref: str) -> bool:
        if action_ref and "/" in action_ref and "@" in action_ref:
            ref_part = action_ref.split("@")[1]
            if re.match(r"^[0-9a-f]{40}$", ref_part) or re.match(r"^[0-9a-f]{7,}$", ref_part):
                return False
            return True
        return False

    def _is_untrusted_action(self, action_ref: str) -> bool:
        if not action_ref or "/" not in action_ref:
            return False
        owner = action_ref.split("/")[0].lower()
        return owner not in self.trusted_maintainers

    def _check_for_outdated_action(self, action_ref: str) -> Optional[str]:
        if not action_ref or "@" not in action_ref:
            return None
        action_name = action_ref.split("@")[0]
        current_version = action_ref.split("@")[1]
        if action_name in self.secure_action_patterns:
            recommended = self.secure_action_patterns[action_name]
            current_v = current_version.replace("v", "").split(".")[0] if "v" in current_version else current_version
            recommended_v = recommended.replace("v", "").split(".")[0] if "v" in recommended else recommended
            try:
                if int(current_v) < int(recommended_v):
                    return f"Update to {action_name}{recommended} or newer for better security and features"
            except (ValueError, IndexError):
                return f"Consider using {action_name}{recommended} for better security and features"
        return None

    def _has_elevated_permissions(self, job_data: Dict[str, Any]) -> bool:
        if not isinstance(job_data, dict):
            return False
        if "permissions" in job_data:
            permissions = job_data["permissions"]
            if permissions == "write-all" or permissions == "*":
                return True
            if isinstance(permissions, dict):
                for perm, value in permissions.items():
                    if value == "write":
                        return True
        return False

    def _has_unverified_script_download(self, command: str) -> bool:
        unsafe_patterns = [
            r"curl\s+-s.*\|\s*bash",
            r"curl\s+-s.*\|\s*sh",
            r"wget\s+-q.*\|\s*bash",
            r"wget\s+-q.*\|\s*sh",
            r"curl\s+.*\s+>\s+[\w\/\.\-]+\.sh\s*(?!&&\s*sha256sum|&&\s*gpg)",
            r"wget\s+.*\s+-O\s+[\w\/\.\-]+\.sh\s*(?!&&\s*sha256sum|&&\s*gpg)"
        ]
        return any(re.search(pattern, command, re.IGNORECASE) for pattern in unsafe_patterns)

    def _is_latest_or_no_tag(self, image_ref: str) -> bool:
        image_str = str(image_ref)
        if ":latest" in image_str:
            return True
        if ":" not in image_str or re.search(r":[0-9]+$", image_str):
            return True
        return False

    def _is_untrusted_registry(self, image_ref: str) -> bool:
        image_str = str(image_ref)
        trusted_registries = [
            "docker.io/library",
            "mcr.microsoft.com",
            "gcr.io/google",
            "quay.io/",
            "registry.access.redhat.com",
            "registry.gitlab.com",
            "ghcr.io"
        ]
        for registry in trusted_registries:
            if registry in image_str:
                return False
        if "/" in image_str and not image_str.startswith("docker.io/library"):
            return True
        return False

    def _is_third_party_azure_task(self, task_name: str) -> bool:
        official_prefixes = ["azure", "vstest", "msbuild", "dotnet", "nuget", "vsbuild", "vs"]
        for prefix in official_prefixes:
            if task_name.lower().startswith(prefix):
                return False
        official_tasks = [
            "PublishBuildArtifacts", "DownloadBuildArtifacts", "CopyFiles",
            "PublishTestResults", "PublishCodeCoverageResults", "ArchiveFiles",
            "ExtractFiles", "CmdLine", "PowerShell", "Bash"
        ]
        if task_name in official_tasks:
            return False
        return True

    def _has_version_pinned(self, step: Dict[str, Any]) -> bool:
        return "version" in step and step["version"] != "latest"

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

    def _find_azure_task_line(self, file_lines: List[str], job_index: int, step_index: int) -> int:
        job_count = -1
        job_line = -1
        step_count = -1
        for i, line in enumerate(file_lines):
            if "- job:" in line:
                job_count += 1
                if job_count == job_index:
                    job_line = i
                    break
        if job_line < 0:
            return -1
        steps_line = -1
        for i in range(job_line, len(file_lines)):
            if "steps:" in file_lines[i]:
                steps_line = i
                break
        if steps_line < 0:
            return -1
        for i in range(steps_line + 1, len(file_lines)):
            if "- task:" in file_lines[i] or "- script:" in file_lines[i] or "- bash:" in file_lines[i] or "- powershell:" in file_lines[i]:
                step_count += 1
                if step_count == step_index:
                    return i
            if line.strip() and not line.strip().startswith("-") and not line.strip().startswith(" "):
                break
        return -1

    def _find_resource_line(self, file_lines: List[str], resource_type: str, resource_index: int) -> int:
        resources_line = -1
        resource_type_line = -1
        resource_count = -1
        for i, line in enumerate(file_lines):
            if line.strip() == "resources:":
                resources_line = i
                break
        if resources_line < 0:
            return -1
        for i in range(resources_line + 1, len(file_lines)):
            if line.strip() == f"{resource_type}:":
                resource_type_line = i
                break
        if resource_type_line < 0:
            return -1
        for i in range(resource_type_line + 1, len(file_lines)):
            if line.strip().startswith("- "):
                resource_count += 1
                if resource_count == resource_index:
                    return i
            if line.strip() and not line.strip().startswith("-") and not line.strip().startswith(" "):
                break
        return -1

    def _find_line_with_content(self, file_lines: List[str], content: str, start_line: int) -> int:
        for i in range(start_line, len(file_lines)):
            if content in file_lines[i]:
                return i
        return -1