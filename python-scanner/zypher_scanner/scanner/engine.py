import os
import importlib
import inspect
import json
from typing import Dict, List, Any, Optional

from .parser import PipelineParser
from .rules.base_rule import BaseRule, Finding
from .utils import format_findings_report, format_findings_report_sequential, LoadingAnimation


class ScannerEngine:
    """
    Main engine for the CI/CD pipeline vulnerability scanner.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the scanner engine.
        
        Args:
            config_path: Path to the scanner configuration file (optional)
        """
        self.parser = PipelineParser()
        self.rules = []
        self.config = self._load_config(config_path)
        self._load_rules()
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        Load scanner configuration.
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Dictionary containing scanner configuration
        """
        default_config = {
            "severity_threshold": "LOW",  # Minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL)
            "rules_directory": "rules",
            "enabled_rules": [],          # Empty list means all rules are enabled
            "disabled_rules": [],         # Rules to disable
            "report_format": "text",      # Output format (text, json)
            "max_findings": 100           # Maximum number of findings to report
        }
        
        if not config_path or not os.path.isfile(config_path):
            return default_config
            
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                
            # Merge user config with default config
            for key, value in user_config.items():
                default_config[key] = value
                
            return default_config
        except Exception as e:
            print(f"Error loading configuration: {str(e)}. Using default configuration.")
            return default_config
            
    def _load_rules(self):
        """
        Load all rule classes dynamically.
        """
        self.rules = []
        
        # Get the path to the rules directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        rules_dir = os.path.join(current_dir, self.config["rules_directory"])
        
        # Get all Python files in the rules directory
        rule_files = [f[:-3] for f in os.listdir(rules_dir) 
                     if f.endswith('.py') and f != '__init__.py' and f != 'base_rule.py']
        
        # Import each rule module and instantiate rule classes
        for rule_file in rule_files:
            try:
                # Skip disabled rules
                if rule_file in self.config["disabled_rules"]:
                    continue
                    
                # Only load enabled rules if the list is not empty
                if self.config["enabled_rules"] and rule_file not in self.config["enabled_rules"]:
                    continue
                
                # Import the rule module
                module_name = f".rules.{rule_file}"
                module = importlib.import_module(module_name, package=__package__)
                
                # Find all classes in the module that inherit from BaseRule
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, BaseRule) and 
                        obj != BaseRule):
                        # Instantiate the rule class and add it to the rules list
                        self.rules.append(obj())                        
            except Exception as e:
                print(f"Error loading rule '{rule_file}': {str(e)}")
                
    def scan_pipeline(self, file_path: str, show_progress: bool = True) -> List[Finding]:
        """
        Scan a pipeline configuration file for vulnerabilities.
        
        Args:
            file_path: Path to the pipeline configuration file
            show_progress: Whether to show progress and loading animations
            
        Returns:
            List of Finding objects representing detected vulnerabilities
        """
        try:            # Initialize loading animation
            if show_progress:
                parsing_loader = LoadingAnimation("Parsing pipeline configuration file")
                parsing_loader.start()
                
            try:
                # Parse the pipeline configuration file
                pipeline_data, file_lines = self.parser.parse_file(file_path)
                
                # Detect the pipeline type
                pipeline_type = self.parser.detect_pipeline_type(pipeline_data)
            finally:
                # Stop the parsing animation
                if show_progress:
                    parsing_loader.stop()
                    print(f"Pipeline type detected: {pipeline_type}")
            
            # Run all applicable rules against the pipeline configuration
            all_findings = []
            total_rules = len(self.rules)
            
            for i, rule in enumerate(self.rules, 1):
                try:
                    # Show progress for each rule
                    if show_progress:
                        rule_name = rule.__class__.__name__
                        rule_loader = LoadingAnimation(f"Running rule {i}/{total_rules}: {rule_name}")
                        rule_loader.start()
                    
                    # Run the rule
                    findings = rule.scan(pipeline_data, file_lines, file_path)
                    all_findings.extend(findings)
                    
                    # Stop the rule animation
                    if show_progress:
                        rule_loader.stop()
                        if findings:
                            print(f"✓ Rule {rule_name} found {len(findings)} issues")
                        else:
                            print(f"✓ Rule {rule_name} completed")
                            
                except Exception as e:
                    # Stop the rule animation on error
                    if show_progress:
                        rule_loader.stop()
                    print(f"Error running rule '{rule.__class__.__name__}': {str(e)}")
            
            if show_progress:
                sorting_loader = LoadingAnimation("Organizing and prioritizing findings")
                sorting_loader.start()
                
            try:
                # Sort findings by severity and line number
                severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                all_findings.sort(
                    key=lambda f: (severity_order.get(f.severity, 4), f.line_number)
                )
                
                # Limit the number of findings if necessary
                if self.config["max_findings"] > 0 and len(all_findings) > self.config["max_findings"]:
                    all_findings = all_findings[:self.config["max_findings"]]
            finally:
                # Stop the sorting animation
                if show_progress:
                    sorting_loader.stop()
                    print(f"Analysis complete! Found {len(all_findings)} potential vulnerabilities.")
                    
            return all_findings
                
        except Exception as e:
            raise RuntimeError(f"Error scanning pipeline: {str(e)}")
    def generate_report(self, findings: List[Finding], output_format: Optional[str] = None, sequential: bool = False) -> str:
        """
        Generate a report of the findings.
        
        Args:
            findings: List of Finding objects
            output_format: Report format ('text' or 'json')
            sequential: Whether to display findings sequentially with loading effects
            
        Returns:
            Formatted report as a string (None if using sequential display)
        """
        format_type = output_format or self.config["report_format"]
        
        if format_type == "json":
            # Convert findings to dictionary
            findings_dict = [finding.to_dict() for finding in findings]
            return json.dumps(findings_dict, indent=2)
        else:            # Generate text report
            if sequential:
                format_findings_report_sequential(findings)
                return None
            else:
                return format_findings_report(findings)