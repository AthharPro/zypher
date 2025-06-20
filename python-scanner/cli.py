import os
import sys
import argparse
import json
from typing import List, Dict, Any, Optional

# Add the parent directory to the path to import the scanner module
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# print(f"Python path: {sys.path}")
# print(f"Looking for modules in: {current_dir}")

try:
    from zypher_scanner.scanner.engine import ScannerEngine
    from zypher_scanner.scanner.utils import Colors
    print("Successfully imported scanner modules")
except ImportError as e:
    print(f"Error importing modules: {e}")
    print(f"Files in current directory: {os.listdir(current_dir)}")
    scanner_dir = os.path.join(current_dir, 'zypher_scanner')
    if os.path.exists(scanner_dir):
        print(f"Files in zypher_scanner directory: {os.listdir(scanner_dir)}")
    sys.exit(1)


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Zypher - CI/CD Pipeline Configuration Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py -f pipeline.yml
  python cli.py -f .github/workflows/ci.yml -o report.json -f json
  python cli.py -d ./pipelines -r text
"""
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-f", "--file", 
        help="Path to a CI/CD pipeline configuration file to scan"
    )
    input_group.add_argument(
        "-d", "--directory", 
        help="Path to a directory containing pipeline configuration files to scan"
    )
    
    parser.add_argument(
        "-c", "--config", 
        help="Path to scanner configuration file"
    )
    parser.add_argument(
        "-o", "--output", 
        help="Path to write the report to (default: stdout)"
    )
    parser.add_argument(
        "-r", "--report-format", 
        choices=["text", "json"],
        default="text",
        help="Report format (default: text)"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "-s", "--sequential", 
        action="store_true",
        help="Display findings sequentially with loading animations"
    )
    
    return parser.parse_args()


def find_pipeline_files(directory: str) -> List[str]:
    """Find all YAML pipeline configuration files in a directory"""
    pipeline_files = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                pipeline_files.append(os.path.join(root, file))
                
    return pipeline_files


def scan_single_file(file_path: str, scanner: ScannerEngine, report_format: str, verbose: bool, sequential: bool = False) -> Dict:
    """Scan a single pipeline configuration file"""
    try:
        if verbose:
            print(f"Scanning: {file_path}")
            
        findings = scanner.scan_pipeline(file_path, show_progress=verbose or sequential)
        report = scanner.generate_report(findings, report_format, sequential=sequential)
        
        result = {
            "file_path": file_path,
            "findings_count": len(findings),
            "report": report if report is not None else ""
        }
        
        return result
    except Exception as e:
        if verbose:
            print(f"Error scanning {file_path}: {str(e)}")
        return {
            "file_path": file_path,
            "error": str(e),
            "findings_count": 0,
            "report": ""
        }


def main():
    """Main entry point for the CLI"""
    args = parse_arguments()
    
    # Print banner
    if args.output is None:  # Only show banner when outputting to stdout
        colors = Colors.supports_color()
        cyan = Colors.CYAN if colors else ""
        bold = Colors.BOLD if colors else ""
        reset = Colors.RESET if colors else ""
        
        banner = f"""
{cyan}{bold}███████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗ 
╚══███╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗
  ███╔╝  ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝
 ███╔╝    ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
███████╗   ██║   ██║     ██║  ██║███████╗██║  ██║
╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{reset}
                                                  
CI/CD Pipeline Vulnerability Scanner
"""
        print(banner)
    
    try:
        # Initialize the scanner
        scanner = ScannerEngine(args.config)
        
        # Determine files to scan
        if args.file:
            files_to_scan = [os.path.abspath(args.file)]
        else:
            directory = os.path.abspath(args.directory)
            files_to_scan = find_pipeline_files(directory)
            
        if not files_to_scan:
            print(f"No pipeline configuration files found to scan.")
            return 1
            
        if args.verbose:
            print(f"Found {len(files_to_scan)} files to scan.")
          # Scan files
        results = []
        for file_path in files_to_scan:
            result = scan_single_file(file_path, scanner, args.report_format, args.verbose, args.sequential)
            results.append(result)
        
        # Generate overall report
        if len(results) == 1:
            # Single file report
            output = results[0]["report"]
        else:
            # Multiple files report
            if args.report_format == "json":
                output = json.dumps(results, indent=2)
            else:
                # Text format
                parts = []
                for result in results:
                    if "error" in result:
                        parts.append(f"File: {result['file_path']}\nError: {result['error']}\n")
                    else:
                        parts.append(f"File: {result['file_path']}\nFindings: {result['findings_count']}\n")
                        if result["findings_count"] > 0:
                            parts.append(result["report"])
                            parts.append("\n" + "=" * 80 + "\n")
                output = "\n".join(parts)
          # Output the report
        if args.output and not args.sequential:
            # Only write to output file if not using sequential display
            with open(args.output, 'w') as f:
                f.write(output)
            if args.verbose:
                print(f"Report written to {args.output}")
        elif not args.sequential:
            # Only print output if not using sequential display (which already prints)
            print(output)
        
        # Return non-zero exit code if any findings were found
        total_findings = sum(result.get("findings_count", 0) for result in results)
        return 1 if total_findings > 0 else 0
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())