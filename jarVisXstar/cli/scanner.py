import os
import re
import ast
import json
import sys
from pathlib import Path

class GodScanner:
    def __init__(self, target_dir):
        self.target_dir = Path(target_dir)
        self.secrets_patterns = [
            re.compile(r'(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', re.I),
            re.compile(r'(api_key|apikey|secret_key|secret)\s*=\s*["\'][^"\']+["\']', re.I),
            re.compile(r'token\s*=\s*["\'][^"\']+["\']', re.I),
            re.compile(r'aws_secret|aws_key|aws_access_key', re.I),
            re.compile(r'slack_webhook|discord_webhook|telegram_bot_token', re.I),
            re.compile(r'private_key|rsa_private|pgp_private', re.I),
        ]
        self.dangerous_calls = [
            'eval', 'exec', 'compile', '__import__', 'os.system', 'os.popen',
            'subprocess.call', 'subprocess.Popen', 'subprocess.run',
            'execfile', 'input', 'raw_input', 'pickle.loads', 'pickle.load',
            'yaml.load', 'yaml.dump', 'marshal.loads', 'marshal.load',
        ]

    def scan(self):
        results = {'secrets': [], 'dangerous': [], 'files': []}
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith('.py') or file.endswith('.txt') or file.endswith('.json') or file.endswith('.env'):
                    filepath = Path(root) / file
                    self._scan_file(filepath, results)
        return results

    def _scan_file(self, filepath, results):
        try:
            content = filepath.read_text(encoding='utf-8')
        except:
            return
        results['files'].append(str(filepath))
        for pattern in self.secrets_patterns:
            for match in pattern.finditer(content):
                results['secrets'].append({'file': str(filepath), 'match': match.group(), 'line': content.count('\n', 0, match.start()) + 1})
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and hasattr(node.func, 'id'):
                    if node.func.id in self.dangerous_calls:
                        results['dangerous'].append({'file': str(filepath), 'call': node.func.id, 'line': node.lineno})
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in self.dangerous_calls:
                        results['dangerous'].append({'file': str(filepath), 'call': f"{node.func.value.id}.{node.func.attr}" if isinstance(node.func.value, ast.Name) else node.func.attr, 'line': node.lineno})
        except:
            pass

    def report(self, output_format='json'):
        results = self.scan()
        if output_format == 'json':
            return json.dumps(results, indent=2)
        elif output_format == 'text':
            text = f"SCAN COMPLETE: {len(results['files'])} files\n"
            text += f"SECRETS FOUND: {len(results['secrets'])}\n"
            for s in results['secrets']:
                text += f"  {s['file']}:{s['line']} - {s['match']}\n"
            text += f"DANGEROUS CALLS: {len(results['dangerous'])}\n"
            for d in results['dangerous']:
                text += f"  {d['file']}:{d['line']} - {d['call']}\n"
            return text
        return str(results)