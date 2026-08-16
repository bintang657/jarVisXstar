import re
import bleach
from sqlalchemy import text
from bs4 import BeautifulSoup
import html
import json
import os

class GodSanitizer:
    def __init__(self, db_engine=None):
        self.engine = db_engine
        self.allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'ul', 'ol', 'li', 'a', 'img', 'code', 'pre']
        self.allowed_attrs = {'a': ['href', 'title', 'rel'], 'img': ['src', 'alt', 'width', 'height']}

    def sql_parameterized(self, query, params):
        if self.engine is None:
            raise RuntimeError("DB engine required for parameterized queries")
        stmt = text(query)
        return stmt.bindparams(**params)

    def sql_escape(self, value, context='string'):
        if context == 'string':
            return value.replace("'", "''")
        elif context == 'identifier':
            return re.sub(r'[^a-zA-Z0-9_]', '', value)
        elif context == 'like':
            return value.replace('%', '\\%').replace('_', '\\_').replace("'", "''")
        elif context == 'json':
            return json.dumps(value).replace("'", "''")
        return value

    def xss_deep_clean(self, html_content):
        cleaned = bleach.clean(html_content, tags=self.allowed_tags, attributes=self.allowed_attrs, strip=True)
        soup = BeautifulSoup(cleaned, 'html.parser')
        for tag in soup.find_all(True):
            for attr in list(tag.attrs):
                if attr.lower().startswith('on') or attr.lower() in ['href', 'src', 'action'] and tag[attr].strip().lower().startswith(('javascript:', 'data:', 'vbscript:')):
                    del tag[attr]
            if tag.name in ['script', 'style', 'iframe', 'object', 'embed', 'form', 'input', 'button']:
                tag.decompose()
        return html.escape(str(soup), quote=False)

    def command_escape(self, cmd):
        safe = re.sub(r'[^a-zA-Z0-9\s\-_.\/]', '', cmd)
        parts = safe.split()
        quoted_parts = [f'"{p}"' if not p.startswith('"') else p for p in parts]
        return ' '.join(quoted_parts)

    def path_escape(self, path):
        normalized = os.path.normpath(path)
        if '..' in normalized or normalized.startswith('/') or normalized.startswith('\\'):
            raise ValueError("Path traversal attempt")
        return normalized