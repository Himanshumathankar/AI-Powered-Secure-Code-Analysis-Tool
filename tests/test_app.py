"""
Tests for the Flask web application routes.
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from app import app as flask_app


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.test_client() as c:
        yield c


class TestIndexRoute:
    def test_get_returns_200(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_contains_form(self, client):
        r = client.get("/")
        assert b"analyzeForm" in r.data or b"Analyse" in r.data


class TestAnalyzeRoute:
    def test_post_with_code_redirects_to_result(self, client):
        r = client.post("/analyze", data={"code": "import os\nos.system('ls')"})
        assert r.status_code == 200
        assert b"SecureAI" in r.data or b"finding" in r.data.lower() or b"result" in r.data.lower()

    def test_post_empty_code_redirects(self, client):
        r = client.post("/analyze", data={"code": "   "})
        assert r.status_code in (302, 200)

    def test_post_with_language_hint(self, client):
        r = client.post("/analyze", data={"code": "eval(user_input)", "language": "js"})
        assert r.status_code == 200


class TestApiAnalyzeRoute:
    def test_returns_json(self, client):
        payload = {"code": "password = 'abc123'", "filename": "test.py"}
        r = client.post("/api/analyze", json=payload)
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "vulnerabilities" in data
        assert "overall_risk" in data

    def test_no_code_returns_400(self, client):
        r = client.post("/api/analyze", json={})
        assert r.status_code == 400
        data = json.loads(r.data)
        assert "error" in data

    def test_sql_injection_detected_via_api(self, client):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        r = client.post("/api/analyze", json={"code": code, "filename": "q.py"})
        data = json.loads(r.data)
        titles = [v["title"] for v in data["vulnerabilities"]]
        assert any("SQL" in t for t in titles)

    def test_clean_code_returns_info_risk(self, client):
        r = client.post("/api/analyze", json={"code": "x = 1 + 2", "filename": "x.py"})
        data = json.loads(r.data)
        assert data["overall_risk"] == "INFO"
