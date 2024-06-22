# Python Code Vulnerability Scanner

This is a simple Python-based code scanner to detect common vulnerabilities in Python code such as insecure imports, SQL injection patterns, and XSS patterns.

## Project Structure

code_scanner/
├── scanner/
│ ├── init.py
│ ├── cli.py
│ ├── scanner.py
│ └── tests.py
└── README.md


## Usage

### Running the Scanner

To scan a file or directory for vulnerabilities, run the following command:

```bash
python scanner/cli.py PATH
