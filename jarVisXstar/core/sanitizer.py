import bleach
import re
from typing import Union, Any

class SuperSanitizer:
    @staticmethod
    def xss_clean(data: Any) -> Any:
        if isinstance(data, str):
            clean = bleach.clean(data, tags=[], attributes={}, strip=True)
            clean = re.sub(r"(?i)javascript\s*:", "", clean)
            clean = re.sub(r"(?i)on\w+\s*=", "", clean)
            clean = clean.replace("\x00", "")
            return clean
        elif isinstance(data, dict):
            return {k: SuperSanitizer.xss_clean(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [SuperSanitizer.xss_clean(item) for item in data]
        return data

    @staticmethod
    def sql_escape(value: str) -> str:
        dangerous = ["'", '"', "\\", ";", "--", "/*", "*/", "xp_", "exec", "union", "select"]
        for d in dangerous:
            value = value.replace(d, "")
        return value

    @staticmethod
    def command_escape(value: str) -> str:
        chars = ["&", "|", ";", "$", "`", ">", "<", "(", ")", "\n", "\r"]
        for c in chars:
            value = value.replace(c, "")
        return value