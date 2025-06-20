import os
import sys
from typing import List, Dict, Any
import textwrap
from datetime import datetime
import time
import threading

from .rules.base_rule import Finding

# ANSI color codes for terminal output
class Colors:
    RESET = "\033[0m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    
    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    
    @staticmethod
    def supports_color() -> bool:
        """Check if the terminal supports color output"""
        # Windows 10 or later with colorama installed supports colors
        if sys.platform == "win32" and sys.getwindowsversion().build >= 10586:
            return True
        # Check for ANSI color support in other platforms
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def get_severity_color(severity: str) -> str:
    """Get the appropriate color for a severity level"""
    severity_colors = {
        "CRITICAL": Colors.BG_RED + Colors.WHITE,
        "HIGH": Colors.RED + Colors.BOLD,
        "MEDIUM": Colors.YELLOW + Colors.BOLD,
        "LOW": Colors.CYAN
    }
    return severity_colors.get(severity, Colors.WHITE)


def format_findings_report(findings: List[Finding]) -> str:
    """
    Format a list of findings into a user-friendly report.
    
    Args:
        findings: List of Finding objects
        
    Returns:
        Formatted report as a string
    """
    if not findings:
        return "No vulnerabilities found!"
        
    use_colors = Colors.supports_color()
    
    # Count findings by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        if finding.severity in severity_counts:
            severity_counts[finding.severity] += 1
    
    # Generate the report header
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = [
        "=" * 80,
        f"ZYPHER CI/CD PIPELINE VULNERABILITY SCAN REPORT",
        f"Generated on: {current_time}",
        f"Total findings: {len(findings)}",
        "-" * 80,
        f"Severity breakdown:",
        f"  CRITICAL: {severity_counts['CRITICAL']}",
        f"  HIGH: {severity_counts['HIGH']}",
        f"  MEDIUM: {severity_counts['MEDIUM']}",
        f"  LOW: {severity_counts['LOW']}",
        "=" * 80,
        ""
    ]
    
    # Generate the findings section
    findings_section = []
    for i, finding in enumerate(findings, 1):
        severity_color = get_severity_color(finding.severity) if use_colors else ""
        reset_color = Colors.RESET if use_colors else ""
        
        # Get file name without full path
        file_name = os.path.basename(finding.filepath)
        
        # Format the finding
        finding_text = [
            f"{i}. [{severity_color}{finding.severity}{reset_color}] {finding.rule_id}: {finding.description}",
            f"   Location: {file_name}:{finding.line_number}",
            f"   Code snippet: {finding.snippet}",
            f"   Recommendation: {finding.recommendation}",
            ""
        ]
        
        findings_section.extend(finding_text)
    
    # Combine everything into the final report
    report = "\n".join(header + findings_section)
    return report


def wrap_text(text: str, width: int = 80) -> str:
    """
    Wrap text to a specified width.
    
    Args:
        text: Text to wrap
        width: Width to wrap to
        
    Returns:
        Wrapped text
    """
    return textwrap.fill(text, width=width)


def find_line_with_content(file_lines: List[str], content: str, start_line: int = 0) -> int:
    """
    Find a line number containing specific content.
    
    Args:
        file_lines: List of file lines
        content: Content to search for
        start_line: Line to start searching from
        
    Returns:
        Line number (0-based) or -1 if not found
    """
    for i in range(start_line, len(file_lines)):
        if content in file_lines[i]:
            return i
    return -1


def is_yaml_file(file_path: str) -> bool:
    """
    Check if a file is a YAML file based on extension.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if the file is a YAML file, False otherwise
    """
    extension = os.path.splitext(file_path)[1].lower()
    return extension in ['.yml', '.yaml']

class LoadingAnimation:
    """
    Class to display a loading animation in the terminal.
    """
    def __init__(self, message="Loading", animation_chars=None):
        """
        Initialize the loading animation.
        
        Args:
            message: The message to display before the animation
            animation_chars: Characters to use for the animation
        """
        self.message = message
        # Use simpler animation characters that work better in Windows terminals
        self.animation_chars = animation_chars or ["-", "\\", "|", "/"]
        self.running = False
        self.thread = None
        
    def start(self):
        """Start the loading animation."""
        self.running = True
        self.thread = threading.Thread(target=self._animate)
        self.thread.daemon = True  # Thread will exit when the main program exits
        self.thread.start()
        
    def stop(self):
        """Stop the loading animation."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
            # Clear the animation line
            sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")
            sys.stdout.flush()
    def _animate(self):
        """Animation loop."""
        i = 0
        use_colors = Colors.supports_color()
        cyan = Colors.CYAN if use_colors else ""
        reset = Colors.RESET if use_colors else ""
        
        while self.running:
            char = self.animation_chars[i % len(self.animation_chars)]
            sys.stdout.write(f"\r{cyan}[{char}]{reset} {self.message}")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1


def format_findings_report_sequential(findings: List[Finding], delay: float = 0.5) -> None:
    """
    Display findings one by one with a delay between each.
    
    Args:
        findings: List of Finding objects
        delay: Time delay between displaying findings (seconds)
    """
    if not findings:
        print("No vulnerabilities found!")
        return
        
    use_colors = Colors.supports_color()
    
    # Count findings by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        if finding.severity in severity_counts:
            severity_counts[finding.severity] += 1
    
    # Show analyzing animation
    analyzing_loader = LoadingAnimation("Analyzing scan results")
    analyzing_loader.start()
    time.sleep(1.0)  # Show animation for a moment
    analyzing_loader.stop()
    
    # Generate and display the report header
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = [
        "=" * 80,
        f"ZYPHER CI/CD PIPELINE VULNERABILITY SCAN REPORT",
        f"Generated on: {current_time}",
        f"Total findings: {len(findings)}",
        "-" * 80,
        f"Severity breakdown:",
        f"  CRITICAL: {severity_counts['CRITICAL']}",
        f"  HIGH: {severity_counts['HIGH']}",
        f"  MEDIUM: {severity_counts['MEDIUM']}",
        f"  LOW: {severity_counts['LOW']}",
        "=" * 80,
        ""
    ]
    
    # Print the header
    print("\n".join(header))
    
    # Sort findings by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(findings, key=lambda f: (severity_order.get(f.severity, 4), f.line_number))
    
    print("\nDisplaying findings one by one...\n")
    time.sleep(0.5)
    
    # Generate and display findings one by one with animation
    for i, finding in enumerate(sorted_findings, 1):
        severity_color = get_severity_color(finding.severity) if use_colors else ""
        reset_color = Colors.RESET if use_colors else ""
        
        # Get file name without full path
        file_name = os.path.basename(finding.filepath)
        
        # Use a loading animation before showing the finding
        loader = LoadingAnimation(f"Processing finding {i}/{len(findings)}: {finding.rule_id}")
        loader.start()
        time.sleep(delay)  # Simulate processing time
        loader.stop()
        
        # Format the finding
        finding_text = [
            f"{i}. [{severity_color}{finding.severity}{reset_color}] {finding.rule_id}: {finding.description}",
            f"   Location: {file_name}:{finding.line_number}",
            f"   Code snippet: {finding.snippet}",
            f"   Recommendation: {finding.recommendation}",
            ""
        ]
        
        # Print the finding
        print("\n".join(finding_text))
        
        # Only add a small delay between findings
        if i < len(findings):
            time.sleep(delay / 2)