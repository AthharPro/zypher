import os
import yaml
from typing import Dict, List, Tuple, Any


class PipelineParser:
    """
    Parser for CI/CD pipeline configuration files.
    """
    
    def __init__(self):
        self.supported_formats = ['.yml', '.yaml']
        
    def validate_file(self, file_path: str) -> bool:
        """
        Validate if the file is a supported pipeline configuration file.
        
        Args:
            file_path: Path to the pipeline configuration file
            
        Returns:
            True if the file is a valid pipeline configuration file, False otherwise
        """
        if not os.path.isfile(file_path):
            return False
            
        _, file_ext = os.path.splitext(file_path)
        if file_ext.lower() not in self.supported_formats:
            return False
            
        return True
        
    def parse_file(self, file_path: str) -> Tuple[Dict[str, Any], List[str]]:
        """
        Parse a pipeline configuration file.
        
        Args:
            file_path: Path to the pipeline configuration file
            
        Returns:
            A tuple containing the parsed pipeline configuration and the raw file lines
        """
        if not self.validate_file(file_path):
            raise ValueError(f"Invalid pipeline file: {file_path}")
            
        try:
            # Read the raw file content
            with open(file_path, 'r', encoding='utf-8') as f:
                file_lines = f.readlines()
                
            # Parse the YAML content
            with open(file_path, 'r', encoding='utf-8') as f:
                pipeline_data = yaml.safe_load(f)
                
            if pipeline_data is None:
                pipeline_data = {}
                
            return pipeline_data, file_lines
                
        except yaml.YAMLError as e:
            line_number = e.problem_mark.line + 1 if hasattr(e, 'problem_mark') else None
            error_msg = f"YAML parsing error"
            if line_number:
                error_msg += f" at line {line_number}"
            if hasattr(e, 'problem'):
                error_msg += f": {e.problem}"
                
            raise ValueError(f"{error_msg} in file: {file_path}")
        except Exception as e:
            raise ValueError(f"Error parsing pipeline file: {str(e)}")
    
    def detect_pipeline_type(self, pipeline_data: Dict[str, Any]) -> str:
        """
        Detect the type of CI/CD pipeline.
        
        Args:
            pipeline_data: The parsed pipeline configuration
            
        Returns:
            A string indicating the pipeline type (e.g., 'github', 'gitlab', 'jenkins', etc.)
        """
        # GitHub Actions detection
        if 'jobs' in pipeline_data and ('on' in pipeline_data or 'name' in pipeline_data):
            return 'github'
            
        # GitLab CI detection
        elif 'stages' in pipeline_data or any(key.endswith(':stage') for key in pipeline_data.keys()):
            return 'gitlab'
            
        # Azure Pipelines detection
        elif 'pool' in pipeline_data or 'trigger' in pipeline_data:
            return 'azure'
            
        # Jenkins Pipeline detection (Jenkinsfile in YAML format)
        elif 'pipeline' in pipeline_data or 'agent' in pipeline_data:
            return 'jenkins'
            
        # CircleCI detection
        elif 'version' in pipeline_data and 'jobs' in pipeline_data and 'workflows' in pipeline_data:
            return 'circleci'
            
        # TravisCI detection
        elif 'language' in pipeline_data or 'script' in pipeline_data:
            return 'travis'
            
        # Default to unknown
        return 'unknown'