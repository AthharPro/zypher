#!/usr/bin/env python
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import json
import os

class VulnerabilityLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding:
    def __init__(
        self,
        rule_id: str,
        severity: str,
        description: str,
        line_number: int,
        filepath: str,
        snippet: str,
        recommendation: str,
        confidence: str = "HIGH"
    ):
        self.rule_id = rule_id
        self.severity = severity
        self.description = description
        self.line_number = line_number
        self.filepath = filepath
        self.snippet = snippet
        self.recommendation = recommendation
        self.confidence = confidence

    def __str__(self):
        return f"[{self.severity}] {self.description} at line {self.line_number}"

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "description": self.description,
            "line_number": self.line_number,
            "filepath": self.filepath,
            "snippet": self.snippet,
            "recommendation": self.recommendation,
            "confidence": self.confidence
        }


class BaseRule(ABC):
    def __init__(self):
        """
        Initialize the rule with metadata from the rule_metadata.json file.
        """
        self.rule_id = None
        self.name = None
        self.description = None
        self.severity = None
        self.remediation = None
        self.owasp_category = None
        self._load_metadata()
    
    def _load_metadata(self):
        """
        Load the rule metadata from the rule_metadata.json file.
        """
        try:
            # Get the path to the rule_metadata.json file - fixed path calculation
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            metadata_path = os.path.join(base_dir, "data", "rule_metadata.json")
            
            # Add a fallback path in case the first one doesn't work
            if not os.path.exists(metadata_path):
                # Try one level higher
                base_dir = os.path.dirname(base_dir)
                metadata_path = os.path.join(base_dir, "data", "rule_metadata.json")
                
            # print(f"Looking for metadata at: {metadata_path}")
            
            # Load the rule metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Find the rule metadata that matches this rule's class name
            rule_name = self.__class__.__name__.lower()
            found_match = False
            
            for rule in metadata["rules"]:
                rule_name_normalized = rule["name"].lower().replace(" ", "_")
                class_name = self.__class__.__name__.lower()
                
                # Try different matching strategies
                if (
                    class_name in rule_name_normalized or 
                    rule_name_normalized in class_name or
                    any(term in class_name for term in rule_name_normalized.split("_"))
                ):
                    self.rule_id = rule["id"]
                    self.name = rule["name"]
                    self.description = rule["description"]
                    self.severity = rule["severity"]
                    self.remediation = rule["remediation"]
                    self.owasp_category = rule["owasp_cicd_top10_category"]
                    print(f"Loaded metadata for rule: {self.__class__.__name__}, severity: {self.severity}")
                    found_match = True
                    break
            
            if not found_match:
                print(f"No matching rule found for: {self.__class__.__name__}")
                # Assign a default severity based on class name patterns
                if "credential" in rule_name or "secret" in rule_name:
                    self.severity = VulnerabilityLevel.CRITICAL
                elif "injection" in rule_name or "execution" in rule_name:
                    self.severity = VulnerabilityLevel.CRITICAL
                elif "dependency" in rule_name or "artifact" in rule_name:
                    self.severity = VulnerabilityLevel.HIGH
                else:
                    self.severity = VulnerabilityLevel.MEDIUM
                    
        except Exception as e:
            print(f"Error loading rule metadata: {e}")
            # Default values if metadata loading fails
            self.rule_id = "UNKNOWN"
            self.name = self.__class__.__name__
            self.description = "No description available"
            self.severity = VulnerabilityLevel.MEDIUM
            self.remediation = "No remediation advice available"
            self.owasp_category = "Unknown"
    
    @abstractmethod
    def scan(self, pipeline_data: Dict[str, Any], file_lines: List[str], file_path: str) -> List[Finding]:
        """
        Scan the pipeline configuration for vulnerabilities.
        
        Args:
            pipeline_data: The parsed YAML pipeline configuration as a dictionary
            file_lines: The raw file content as a list of strings (one per line)
            file_path: Path to the file being scanned
            
        Returns:
            A list of Finding objects representing detected vulnerabilities
        """
        pass
        
    def get_line_for_path(self, pipeline_data: Dict[str, Any], file_lines: List[str], 
                        json_path: List[str]) -> Optional[int]:
        """
        Helper method to find the line number in the file that corresponds to a specific
        path in the parsed YAML dictionary.
        
        This is a simplistic implementation and might not work for complex YAML structures.
        For production use, consider using a YAML parser that preserves line numbers.
        
        Args:
            pipeline_data: The parsed YAML pipeline configuration
            file_lines: The raw file content as a list of strings
            json_path: A list of keys representing the path to the item
            
        Returns:
            The line number (0-based) or None if not found
        """
        # Simple implementation - search for the last element in the path
        if not json_path:
            return None
            
        last_element = json_path[-1]
        
        # Search for the key or value in the file
        for i, line in enumerate(file_lines):
            if str(last_element) in line:
                return i + 1  # Convert to 1-based line numbers
                
        return None
