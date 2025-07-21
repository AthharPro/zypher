from typing import Dict, List, Any

class RuleImproperArtifactIntegrityValidation(BaseRule):
    METADATA = {
        "rule_id": "CICD-VULN-009",
        "rule_name": "Improper Artifact Integrity Validation",
        "severity": "HIGH"
    }

    def __init__(self):
        super().__init__()

    def get_severity(self):
        return self.METADATA["severity"]

    def scan(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan for lack of proper artifact signing and verification in CI/CD pipelines.
        """
        findings = []

        has_docker_build = False
        has_docker_push = False
        has_docker_scan = False
        has_sbom_generation = False
        has_artifact_signing = False

        push_line_num = 1

        # Check for jobs and steps
        if "jobs" in pipeline_data:
            for job_name, job_config in pipeline_data["jobs"].items():
                if "steps" in job_config:
                    for i, step in enumerate(job_config["steps"]):
                        # Check for Docker build/push commands
                        if "run" in step and isinstance(step["run"], str):
                            command = step["run"].lower()
                            # Check for Docker build
                            if "docker build" in command:
                                has_docker_build = True
                            # Check for Docker push
                            if "docker push" in command:
                                has_docker_push = True
                                push_line_num = self._find_line_number(file_lines, "docker push")
                            # Check for image scanning
                            if ("trivy" in command or "clair" in command or "docker scan" in command or 
                                "image scan" in command or "vulnerability scan" in command):
                                has_docker_scan = True
                            # Check for SBOM generation
                            if ("sbom" in command or "cyclonedx" in command or "spdx" in command or 
                                "software bill of materials" in command):
                                has_sbom_generation = True
                            # Check for artifact signing
                            if ("cosign" in command or "sigstore" in command or "sign" in command or 
                                "notary" in command):
                                has_artifact_signing = True

                        # Check for actions related to scanning or signing
                        if "uses" in step:
                            action = step["uses"].lower()
                            if ("scanner" in action or "scan" in action or "security" in action or 
                                "trivy" in action or "clair" in action):
                                has_docker_scan = True
                            if "cosign" in action or "sigstore" in action or "sign" in action:
                                has_artifact_signing = True

        # Add findings if vulnerabilities are detected
        if has_docker_build and has_docker_push and not has_docker_scan:
            findings.append(Finding(
                rule_id=self.METADATA["rule_id"],
                severity=self.get_severity(),
                description="Docker images are being built and pushed without security scanning",
                line_number=push_line_num,
                filepath=file_path,
                snippet=self._get_snippet(file_lines, push_line_num),
                recommendation="Add a container image scanning step before pushing to container registry"
            ))

        if has_docker_push and not has_artifact_signing:
            findings.append(Finding(
                rule_id=self.METADATA["rule_id"],
                severity=self.get_severity(),
                description="Container images are pushed without signing",
                line_number=push_line_num,
                filepath=file_path,
                snippet=self._get_snippet(file_lines, push_line_num),
                recommendation="Add image signing (e.g., with Cosign or Notary) before pushing to a registry"
            ))

        if has_docker_build and not has_sbom_generation:
            findings.append(Finding(
                rule_id=self.METADATA["rule_id"],
                severity=self.get_severity(),
                description="No Software Bill of Materials (SBOM) is being generated",
                line_number=1,
                filepath=file_path,
                snippet="",
                recommendation="Generate an SBOM for your artifacts to track dependencies and potential vulnerabilities"
            ))

        return findings

    def _find_line_number(self, file_lines: List[str], text: str) -> int:
        """Find line number containing the specified text"""
        for i, line in enumerate(file_lines):
            if text in line.lower():
                return i + 1  # Convert to 1-based line numbers
        return 1  # Default to first line if not found

    def _get_snippet(self, file_lines: List[str], line_num: int) -> str:
        """Get the content of a line"""
        if 1 <= line_num <= len(file_lines):
            return file_lines[line_num - 1].strip()
        return ""