"""
Tests for the core analyzer module.
"""

import pytest
import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import analyzer
from config import (
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO,
)


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

class TestDetectLanguage:
    def test_python_extension(self):
        assert analyzer.detect_language("script.py", "") == "Python"

    def test_javascript_extension(self):
        assert analyzer.detect_language("app.js", "") == "JavaScript"

    def test_unknown_extension(self):
        result = analyzer.detect_language("file.xyz", "")
        assert result == "Unknown"

    def test_python_shebang(self):
        code = "#!/usr/bin/env python3\nprint('hi')"
        assert analyzer.detect_language("script", code) == "Python"


# ---------------------------------------------------------------------------
# Static analysis – individual rules
# ---------------------------------------------------------------------------

class TestStaticAnalysisSQLInjection:
    def test_detects_fstring_query(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        vulns = analyzer.run_static_analysis(code)
        assert any(v.title == "Potential SQL Injection" for v in vulns)

    def test_clean_parameterised_query(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        vulns = analyzer.run_static_analysis(code)
        assert not any(v.title == "Potential SQL Injection" for v in vulns)


class TestStaticAnalysisCommandInjection:
    def test_detects_os_system_concat(self):
        code = 'import os\nos.system("echo " + user_input)'
        vulns = analyzer.run_static_analysis(code)
        assert any(v.title == "Potential Command Injection" for v in vulns)


class TestStaticAnalysisHardcodedSecrets:
    def test_detects_hardcoded_password(self):
        code = 'password = "supersecret123"'
        vulns = analyzer.run_static_analysis(code)
        assert any(v.title == "Hardcoded Password" for v in vulns)

    def test_detects_api_key(self):
        code = 'api_key = "sk-abcdefghijklmnop"'
        vulns = analyzer.run_static_analysis(code)
        assert any(v.title == "Hardcoded Secret / API Key" for v in vulns)


class TestStaticAnalysisWeakCrypto:
    def test_detects_md5(self):
        code = "import hashlib\nhashlib.md5(data)"
        vulns = analyzer.run_static_analysis(code)
        assert any("MD5" in v.title for v in vulns)

    def test_detects_sha1(self):
        code = "import hashlib\nhashlib.sha1(data)"
        vulns = analyzer.run_static_analysis(code)
        assert any("SHA-1" in v.title for v in vulns)


class TestStaticAnalysisXSS:
    def test_detects_innerhtml(self):
        code = "element.innerHTML = userInput"
        vulns = analyzer.run_static_analysis(code)
        assert any("XSS" in v.title for v in vulns)


class TestStaticAnalysisEval:
    def test_detects_eval(self):
        code = "eval(user_expression)"
        vulns = analyzer.run_static_analysis(code)
        assert any("eval" in v.title.lower() for v in vulns)


class TestStaticAnalysisPickle:
    def test_detects_pickle_load(self):
        code = "import pickle\ndata = pickle.loads(raw_bytes)"
        vulns = analyzer.run_static_analysis(code)
        assert any("pickle" in v.title.lower() or "Insecure" in v.title for v in vulns)


class TestStaticAnalysisDebug:
    def test_detects_debug_true(self):
        code = "app.run(debug=True)"
        vulns = analyzer.run_static_analysis(code)
        assert any("Debug" in v.title for v in vulns)


# ---------------------------------------------------------------------------
# Clean code
# ---------------------------------------------------------------------------

class TestCleanCode:
    def test_no_false_positives_on_clean_code(self):
        code = '''
def add(a, b):
    """Return the sum of a and b."""
    return a + b

if __name__ == "__main__":
    print(add(1, 2))
'''
        vulns = analyzer.run_static_analysis(code)
        assert vulns == []


# ---------------------------------------------------------------------------
# AnalysisResult / analyse() integration
# ---------------------------------------------------------------------------

class TestAnalyse:
    def test_returns_analysis_result(self):
        code = 'password = "hunter2"\ncursor.execute(f"SELECT * FROM t WHERE id={uid}")'
        result = analyzer.analyse(code, "test.py")
        assert result.language == "Python"
        assert len(result.vulnerabilities) >= 2
        assert result.overall_risk in (SEVERITY_CRITICAL, SEVERITY_HIGH)

    def test_overall_risk_info_for_clean_code(self):
        code = "def greet(name):\n    return f'Hello, {name}'"
        result = analyzer.analyse(code, "greet.py")
        assert result.overall_risk == SEVERITY_INFO

    def test_to_dict_has_expected_keys(self):
        result = analyzer.analyse("x = 1", "x.py")
        d = result.to_dict()
        for key in ("language", "vulnerabilities", "summary", "overall_risk", "total", "counts"):
            assert key in d

    def test_no_duplicate_findings(self):
        code = 'password = "secret"\npassword = "secret"'
        result = analyzer.analyse(code, "dup.py")
        titles = [v.title for v in result.vulnerabilities]
        # Same rule should not appear twice for the same file
        assert len(titles) == len(set(titles))


# ---------------------------------------------------------------------------
# Vulnerability.to_dict
# ---------------------------------------------------------------------------

class TestVulnerabilityToDict:
    def test_to_dict_fields(self):
        v = analyzer.Vulnerability(
            title="Test",
            severity=SEVERITY_HIGH,
            line=10,
            description="desc",
            recommendation="fix",
            cwe="CWE-89",
            source="static",
        )
        d = v.to_dict()
        assert d["title"] == "Test"
        assert d["severity"] == SEVERITY_HIGH
        assert d["line"] == 10
        assert d["cwe"] == "CWE-89"
