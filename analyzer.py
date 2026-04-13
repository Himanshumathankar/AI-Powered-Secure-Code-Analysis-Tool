"""
Core AI-powered and static security analysis engine.
"""

import re
import json
from dataclasses import dataclass, field
from typing import Optional

import config

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Vulnerability:
    """Represents a single detected vulnerability."""
    title: str
    severity: str
    line: Optional[int]
    description: str
    recommendation: str
    cwe: str = ""
    source: str = "static"  # "static" | "ai"

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "line": self.line,
            "description": self.description,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "source": self.source,
        }


@dataclass
class AnalysisResult:
    """Aggregated result of a full analysis pass."""
    language: str
    vulnerabilities: list = field(default_factory=list)
    summary: str = ""
    overall_risk: str = config.SEVERITY_INFO
    ai_available: bool = False

    def to_dict(self) -> dict:
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: config.SEVERITY_ORDER.get(v.severity, 99),
        )
        return {
            "language": self.language,
            "vulnerabilities": [v.to_dict() for v in sorted_vulns],
            "summary": self.summary,
            "overall_risk": self.overall_risk,
            "ai_available": self.ai_available,
            "total": len(self.vulnerabilities),
            "counts": {
                sev: sum(1 for v in self.vulnerabilities if v.severity == sev)
                for sev in [
                    config.SEVERITY_CRITICAL,
                    config.SEVERITY_HIGH,
                    config.SEVERITY_MEDIUM,
                    config.SEVERITY_LOW,
                    config.SEVERITY_INFO,
                ]
            },
        }


# ---------------------------------------------------------------------------
# Static analysis patterns
# ---------------------------------------------------------------------------

STATIC_RULES = [
    # --- Injection ---
    {
        "id": "SQL_INJECTION",
        "title": "Potential SQL Injection",
        "pattern": re.compile(
            r'(execute|query|cursor\.execute)\s*\(\s*[f"\'].*(%s|\{|\+)',
            re.IGNORECASE,
        ),
        "severity": config.SEVERITY_CRITICAL,
        "description": (
            "User-supplied data appears to be concatenated directly into a SQL "
            "query, which may allow an attacker to manipulate the query logic."
        ),
        "recommendation": (
            "Use parameterised queries or prepared statements. "
            "Never build SQL strings by concatenation or f-strings."
        ),
        "cwe": "CWE-89",
    },
    {
        "id": "COMMAND_INJECTION",
        "title": "Potential Command Injection",
        "pattern": re.compile(
            r'(os\.system|subprocess\.(call|run|Popen|check_output))\s*\(.*\+',
            re.IGNORECASE,
        ),
        "severity": config.SEVERITY_CRITICAL,
        "description": (
            "Shell command appears to be constructed with user-controlled input, "
            "which could allow arbitrary command execution."
        ),
        "recommendation": (
            "Pass arguments as a list to subprocess functions and set "
            "shell=False. Validate and sanitise all external input."
        ),
        "cwe": "CWE-78",
    },
    # --- Secrets ---
    {
        "id": "HARDCODED_PASSWORD",
        "title": "Hardcoded Password",
        "pattern": re.compile(
            r'(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
            re.IGNORECASE,
        ),
        "severity": config.SEVERITY_HIGH,
        "description": "A plain-text password appears to be hardcoded in the source.",
        "recommendation": (
            "Store credentials in environment variables or a dedicated secrets "
            "manager. Never commit secrets to version control."
        ),
        "cwe": "CWE-798",
    },
    {
        "id": "HARDCODED_SECRET_KEY",
        "title": "Hardcoded Secret / API Key",
        "pattern": re.compile(
            r'(secret_key|api_key|auth_token|access_token)\s*=\s*["\'][^"\']{8,}["\']',
            re.IGNORECASE,
        ),
        "severity": config.SEVERITY_HIGH,
        "description": "A secret key or API token appears to be hardcoded.",
        "recommendation": (
            "Use environment variables or a secrets manager. "
            "Rotate any exposed credentials immediately."
        ),
        "cwe": "CWE-312",
    },
    # --- Cryptography ---
    {
        "id": "WEAK_HASH_MD5",
        "title": "Use of Weak Hash Algorithm (MD5)",
        "pattern": re.compile(r'\bhashlib\.md5\b|\bMD5\b', re.IGNORECASE),
        "severity": config.SEVERITY_MEDIUM,
        "description": "MD5 is cryptographically broken and unsuitable for security uses.",
        "recommendation": "Replace MD5 with SHA-256 or SHA-3 for all security-sensitive hashing.",
        "cwe": "CWE-327",
    },
    {
        "id": "WEAK_HASH_SHA1",
        "title": "Use of Weak Hash Algorithm (SHA-1)",
        "pattern": re.compile(r'\bhashlib\.sha1\b|\bSHA1\b', re.IGNORECASE),
        "severity": config.SEVERITY_MEDIUM,
        "description": "SHA-1 is deprecated for security use due to collision vulnerabilities.",
        "recommendation": "Upgrade to SHA-256 or SHA-3.",
        "cwe": "CWE-327",
    },
    # --- Web ---
    {
        "id": "XSS_INNERHTML",
        "title": "Potential Cross-Site Scripting (XSS) via innerHTML",
        "pattern": re.compile(r'\.innerHTML\s*=\s*(?![\s]*["\'])', re.IGNORECASE),
        "severity": config.SEVERITY_HIGH,
        "description": (
            "Assigning untrusted data to innerHTML can lead to XSS attacks "
            "that execute arbitrary scripts in the victim's browser."
        ),
        "recommendation": (
            "Use textContent instead of innerHTML, or sanitise input with a "
            "library such as DOMPurify before insertion."
        ),
        "cwe": "CWE-79",
    },
    {
        "id": "EVAL_USAGE",
        "title": "Use of eval()",
        "pattern": re.compile(r'\beval\s*\(', re.IGNORECASE),
        "severity": config.SEVERITY_HIGH,
        "description": (
            "eval() executes arbitrary code and is dangerous when called with "
            "user-supplied or untrusted data."
        ),
        "recommendation": "Avoid eval() entirely. Use safer alternatives such as JSON.parse() for data.",
        "cwe": "CWE-95",
    },
    # --- Path traversal ---
    {
        "id": "PATH_TRAVERSAL",
        "title": "Potential Path Traversal",
        "pattern": re.compile(
            r'open\s*\(.*(\+|format|f["\'])',
            re.IGNORECASE,
        ),
        "severity": config.SEVERITY_HIGH,
        "description": (
            "File paths constructed from user input may allow attackers to "
            "read or write files outside the intended directory."
        ),
        "recommendation": (
            "Validate and sanitise file paths. Use os.path.abspath and confirm "
            "the resolved path starts with the allowed base directory."
        ),
        "cwe": "CWE-22",
    },
    # --- Insecure deserialization ---
    {
        "id": "PICKLE_LOAD",
        "title": "Insecure Deserialization (pickle)",
        "pattern": re.compile(r'\bpickle\.(load|loads)\b', re.IGNORECASE),
        "severity": config.SEVERITY_HIGH,
        "description": (
            "Deserializing untrusted data with pickle can lead to arbitrary "
            "code execution."
        ),
        "recommendation": "Use JSON or another safe format for data exchange. Never unpickle untrusted data.",
        "cwe": "CWE-502",
    },
    # --- Debug / dev artefacts ---
    {
        "id": "DEBUG_ENABLED",
        "title": "Debug Mode Enabled",
        "pattern": re.compile(r'\bdebug\s*=\s*True\b', re.IGNORECASE),
        "severity": config.SEVERITY_MEDIUM,
        "description": "Debug mode exposes stack traces and can leak sensitive information.",
        "recommendation": "Disable debug mode in production. Use environment variables to control this setting.",
        "cwe": "CWE-215",
    },
]


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_EXT_TO_LANG = {
    "py": "Python", "js": "JavaScript", "ts": "TypeScript",
    "java": "Java", "c": "C", "cpp": "C++", "cs": "C#",
    "go": "Go", "rb": "Ruby", "php": "PHP", "swift": "Swift",
    "kt": "Kotlin", "rs": "Rust", "html": "HTML", "sql": "SQL",
}


def detect_language(filename: str, code: str) -> str:
    """Attempt to detect the programming language from filename or shebang."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in _EXT_TO_LANG:
        return _EXT_TO_LANG[ext]
    # Shebang fallback
    first_line = code.splitlines()[0] if code.strip() else ""
    if "python" in first_line:
        return "Python"
    if "node" in first_line or "javascript" in first_line:
        return "JavaScript"
    return "Unknown"


# ---------------------------------------------------------------------------
# Static analyzer
# ---------------------------------------------------------------------------

def run_static_analysis(code: str) -> list[Vulnerability]:
    """Apply regex-based SAST rules to the provided source code."""
    findings: list[Vulnerability] = []
    lines = code.splitlines()

    for rule in STATIC_RULES:
        for lineno, line in enumerate(lines, start=1):
            if rule["pattern"].search(line):
                findings.append(
                    Vulnerability(
                        title=rule["title"],
                        severity=rule["severity"],
                        line=lineno,
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        cwe=rule["cwe"],
                        source="static",
                    )
                )
                break  # Report rule once per file (avoid duplicates)

    return findings


# ---------------------------------------------------------------------------
# AI analysis
# ---------------------------------------------------------------------------

def run_ai_analysis(code: str, language: str) -> tuple[list[Vulnerability], str]:
    """
    Send the code to OpenAI and parse the structured response.

    Returns (vulnerabilities, summary_text).
    Falls back gracefully if the API key is missing or the call fails.
    """
    if not config.OPENAI_API_KEY:
        return [], ""

    try:
        from openai import OpenAI  # lazy import – keeps the module usable without openai installed

        client = OpenAI(api_key=config.OPENAI_API_KEY)

        system_prompt = (
            "You are an expert application security engineer. "
            "Analyze the supplied source code for security vulnerabilities. "
            "Respond with ONLY a valid JSON object with the following structure:\n"
            "{\n"
            '  "summary": "<one-paragraph plain-English summary>",\n'
            '  "vulnerabilities": [\n'
            "    {\n"
            '      "title": "<short title>",\n'
            '      "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",\n'
            '      "line": <line number or null>,\n'
            '      "description": "<detailed description>",\n'
            '      "recommendation": "<how to fix>",\n'
            '      "cwe": "<CWE-XXX or empty string>"\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "If no vulnerabilities are found, return an empty vulnerabilities array."
        )

        user_prompt = f"Language: {language}\n\n```\n{code[:8000]}\n```"

        response = client.chat.completions.create(
            model=config.OPENAI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=2048,
        )

        raw = response.choices[0].message.content.strip()
        # Strip possible markdown code fences
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)

        data = json.loads(raw)
        summary = data.get("summary", "")
        vulns = [
            Vulnerability(
                title=v.get("title", "Unknown"),
                severity=v.get("severity", config.SEVERITY_INFO),
                line=v.get("line"),
                description=v.get("description", ""),
                recommendation=v.get("recommendation", ""),
                cwe=v.get("cwe", ""),
                source="ai",
            )
            for v in data.get("vulnerabilities", [])
        ]
        return vulns, summary

    except Exception:  # noqa: BLE001 – surface any error as empty result
        return [], ""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyse(code: str, filename: str = "code.py") -> AnalysisResult:
    """
    Run both static and AI analysis on *code* and return an AnalysisResult.
    """
    language = detect_language(filename, code)

    static_vulns = run_static_analysis(code)
    ai_vulns, ai_summary = run_ai_analysis(code, language)

    # Merge: avoid flagging the exact same (title, line) pair twice
    seen = {(v.title, v.line) for v in static_vulns}
    merged = list(static_vulns)
    for v in ai_vulns:
        if (v.title, v.line) not in seen:
            merged.append(v)
            seen.add((v.title, v.line))

    # Determine overall risk from highest-severity finding
    overall_risk = config.SEVERITY_INFO
    for sev in [
        config.SEVERITY_CRITICAL,
        config.SEVERITY_HIGH,
        config.SEVERITY_MEDIUM,
        config.SEVERITY_LOW,
    ]:
        if any(v.severity == sev for v in merged):
            overall_risk = sev
            break

    summary = ai_summary or _build_static_summary(merged, language)

    return AnalysisResult(
        language=language,
        vulnerabilities=merged,
        summary=summary,
        overall_risk=overall_risk,
        ai_available=bool(config.OPENAI_API_KEY),
    )


def _build_static_summary(vulns: list[Vulnerability], language: str) -> str:
    if not vulns:
        return (
            f"No security issues were detected in the {language} code by the "
            "static analyzer. Consider enabling AI analysis for deeper insights."
        )
    counts = {}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1
    parts = [f"{c} {s.lower()}" for s, c in counts.items()]
    return (
        f"Static analysis of the {language} code found {len(vulns)} potential "
        f"issue(s): {', '.join(parts)}. Review each finding and apply the "
        "recommended remediation steps."
    )
