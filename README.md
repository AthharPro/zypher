# zypher

Web-Based CI/CD vulnerability scanner

1st -> Pyhton <br>
2nd -> Next.js + Fast API

### Folder structure of python-scanner

``` perl
zypher-scanner/
│
├── scanner/                        # Core logic of the scanner
│   ├── __init__.py
│   ├── engine.py                   # Main scanner engine orchestrating all checks
│   ├── parser.py                   # YAML parsing logic
│   ├── utils.py                    # Common helper functions
│   ├── rules/                      # Folder for all vulnerability detection rules
│   │   ├── __init__.py
│   │   ├── base_rule.py            # Base class/interface for rules
│   │   ├── rule_insufficient_flow_control.py
│   │   ├── rule_inadequate_iam.py
│   │   ├── rule_dependency_chain_abuse.py
│   │   └── ... (others for each OWASP item)
│   └── report_generator.py        # Generates structured scan reports
│
├── tests/                          # Unit & integration tests
│   ├── test_engine.py
│   ├── test_parser.py
│   ├── test_rules/
│   │   └── test_individual_rules.py
│
├── examples/                       # Sample YAML files to test against
│   └── sample_pipeline.yml
│
├── data/                           # Rule metadata, templates, etc.
│   ├── rule_metadata.json
│
├── cli.py                          # Command-line interface to use the tool
├── requirements.txt
├── README.md
└── config.json                     # Configs such as scan depth, logging level, etc.
```
