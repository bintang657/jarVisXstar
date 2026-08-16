import os
import re
import json
import argparse
from pathlib import Path

class Scanner:
    @staticmethod
    def scan(path: str) -> list:
        findings = []
        for root, _, files in os.walk(path):
            for f in files:
                if f.endswith((".py", ".js", ".php", ".go", ".java", ".rb")):
                    full = os.path.join(root, f)
                    try:
                        with open(full, "r", encoding="utf-8", errors="ignore") as file:
                            content = file.read()
                            # Hardcoded secret
                            if re.search(r"(password|passwd|secret|api_key|token)\s*=\s*['\"][^'\"]+['\"]", content):
                                findings.append(f"Hardcoded secret: {full}")
                            # eval/exec/system
                            if re.search(r"\b(eval|exec|system|popen|subprocess\.call|os\.system)\s*\(", content):
                                findings.append(f"Dangerous call: {full}")
                    except:
                        pass
        return findings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=".")
    parser.add_argument("--output", default="scan_report.json")
    args = parser.parse_args()
    findings = Scanner.scan(args.path)
    with open(args.output, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"Scan selesai. {len(findings)} temuan. Laporan: {args.output}")

if __name__ == "__main__":
    main()