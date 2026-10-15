"""Check the tracked publication tree; never read an operator's live secrets."""
import json
from pathlib import Path
import re
import subprocess


def audit(root):
    names = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).decode().split('\0')
    failures = []
    files = 0
    documents = 0
    for name in filter(None, names):
        path = root/name
        if not path.is_file() or path.is_symlink():
            failures.append({'file': name, 'reason': 'missing or linked tracked file'})
            continue
        files += 1
        if (name.startswith(('output/', 'tmp/', 'deploy/runtime/')) or
            re.search(r'(^|/)(\.env|node_modules|\.next)(/|$)', name) or
            path.suffix in {'.db', '.dump', '.pem', '.key', '.p12', '.pfx', '.pyc'}):
            failures.append({'file': name, 'reason': 'runtime or secret-file path'})
        try:
            content = path.read_text()
        except UnicodeDecodeError:
            continue
        if path.suffix.lower() in {'.md', '.rst', '.txt'}:
            documents += 1
        if re.search(r'[\u3400-\u9fff]', content):
            failures.append({'file': name, 'reason': 'non-English CJK text'})
    return {'passed': not failures, 'tracked_files': files, 'documentation_files': documents, 'failures': failures}


if __name__ == '__main__':
    result = audit(Path(__file__).resolve().parents[1])
    print(json.dumps(result))
    raise SystemExit(not result['passed'])
