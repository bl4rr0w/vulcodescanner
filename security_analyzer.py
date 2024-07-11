import typer
import re
import os
from typing import List
import bandit
from bandit.core import manager
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
from tqdm import tqdm

app = typer.Typer()

# Patterns for detection
INSECURE_IMPORTS = [
    "os.system", "subprocess.Popen", "eval", "exec", "pickle.loads",
    "__import__", "importlib.import_module", "builtins.__import__",
    "runpy.run_path", "runpy.run_module"
]

SQL_INJECTION_PATTERNS = [
    r"SELECT.*FROM.*WHERE.*\%s",
    r"INSERT.*INTO.*VALUES.*\%s",
    r"UPDATE.*SET.*WHERE.*\%s",
    r"DELETE.*FROM.*WHERE.*\%s",
    r".*execute\(.*\+.*\)",
    r".*execute\(f[\"'].*\{.*\}.*[\"']\)",
    r".*cursor\.execute\(.*\%.*\)",
    r".*cursor\.executemany\(.*\%.*\)",
    r".*\.raw\(.*\%.*\)"
]

XSS_PATTERNS = [
    r"<script>.*</script>",
    r"javascript:",
    r"onload=",
    r"onerror=",
    r"onmouseover=",
    r"onclick=",
    r"onsubmit=",
    r"onfocus=",
    r"onblur=",
    r"<img.*src=",
    r"<iframe.*src=",
    r"document\.write\(",
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"\.insertAdjacentHTML\(",
    r"\.createContextualFragment\("
]

def read_file(file_path: str) -> str:
    with open(file_path, 'r') as file:
        return file.read()

def detect_insecure_imports(content: str) -> List[str]:
    return [imp for imp in INSECURE_IMPORTS if imp in content]

def detect_sql_injection(content: str) -> List[str]:
    return [pattern for pattern in SQL_INJECTION_PATTERNS if re.search(pattern, content, re.IGNORECASE)]

def detect_xss(content: str) -> List[str]:
    return [pattern for pattern in XSS_PATTERNS if re.search(pattern, content, re.IGNORECASE)]

def run_bandit(file_path: str) -> List[str]:
    b_mgr = manager.BanditManager(bandit.config.BanditConfig(), agg_type='file')
    b_mgr.discover_files([file_path])
    b_mgr.run_tests()
    return [issue.text for issue in b_mgr.get_issue_list()]

def explain_vulnerability(vulnerability_type: str, pattern: str) -> str:
    explanations = {
        "insecure_imports": "This import can lead to arbitrary code execution if used with untrusted input. Attackers can exploit this by injecting malicious code that gets executed.",
        "sql_injection": "This pattern suggests SQL injection vulnerability. Attackers can exploit this by injecting malicious SQL code to manipulate the database.",
        "xss": "This pattern indicates potential Cross-Site Scripting (XSS) vulnerability. Attackers can exploit this by injecting malicious scripts that get executed in the user's browser."
    }
    return explanations.get(vulnerability_type, "Unknown vulnerability type.")

def rate_code_quality(vulnerabilities: dict) -> int:
    total_issues = sum(len(issues) for issues in vulnerabilities.values())
    if total_issues == 0:
        return 100
    elif total_issues <= 5:
        return 80
    elif total_issues <= 10:
        return 60
    elif total_issues <= 15:
        return 40
    else:
        return 20

# Load the AI model and tokenizer
model_name = "mrm8488/codebert-base-finetuned-detect-insecure-code"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

def ai_detect_vulnerabilities(content: str) -> List[dict]:
    inputs = tokenizer(content, return_tensors="pt", truncation=True, padding=True, max_length=512)
    
    with torch.no_grad():
        outputs = model(**inputs)
    
    probabilities = torch.softmax(outputs.logits, dim=1)
    prediction = torch.argmax(probabilities, dim=1).item()
    confidence = probabilities[0][prediction].item()
    
    if prediction == 1:
        return [{
            "type": "Potential Security Vulnerability",
            "description": "The AI model has detected potential security issues in this code.",
            "probability": confidence
        }]
    else:
        return []

@app.command()
def analyze(
    file_paths: List[str] = typer.Argument(..., help="Paths to Python files to analyze"),
    output_format: str = typer.Option("text", help="Output format: text or json")
):
    results = {}
    if 'analyze' in file_paths:
        file_paths.remove('analyze')
    for file_path in tqdm(file_paths, desc="Analyzing files"):
        if not os.path.exists(file_path):
            typer.echo(f"File not found: {file_path}")
            continue
        
        content = read_file(file_path)
        vulnerabilities = {
            "insecure_imports": detect_insecure_imports(content),
            "sql_injection": detect_sql_injection(content),
            "xss": detect_xss(content),
            "bandit_issues": run_bandit(file_path),
            "ai_vulnerabilities": ai_detect_vulnerabilities(content)
        }
        code_quality = rate_code_quality(vulnerabilities)
        results[file_path] = {
            "vulnerabilities": vulnerabilities,
            "code_quality": code_quality
        }
    
    if output_format == "json":
        import json
        typer.echo(json.dumps(results, indent=2))
    else:
        for file_path, data in results.items():
            typer.echo(f"\nFile: {file_path}")
            typer.echo(f"Code Quality: {data['code_quality']}/100")
            for issue_type, detected in data["vulnerabilities"].items():
                if detected:
                    typer.echo(f"  {issue_type.replace('_', ' ').title()}:")
                    if issue_type == "ai_vulnerabilities":
                        for vuln in detected:
                            typer.echo(f"    - {vuln['type']} (Confidence: {vuln['probability']:.2f})")
                            typer.echo(f"      Description: {vuln['description']}")
                    else:
                        for item in detected:
                            typer.echo(f"    - {item}")
                            typer.echo(f"      Explanation: {explain_vulnerability(issue_type, item)}")

if __name__ == "__main__":
    app()