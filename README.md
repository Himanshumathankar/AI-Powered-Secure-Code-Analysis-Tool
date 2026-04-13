# 🔐 AI-Powered Secure Code Analysis Tool

> Detect security vulnerabilities in source code using **static analysis** and **OpenAI GPT-4o** — via a web UI, REST API, or CLI.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.x-green.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-30%20passing-brightgreen.svg)](#running-tests)

---

## Table of Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Detected Vulnerabilities](#detected-vulnerabilities)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Running the Web App](#running-the-web-app)
  - [Using the CLI](#using-the-cli)
  - [REST API](#rest-api)
- [Docker](#docker)
- [Running Tests](#running-tests)
- [How It Works](#how-it-works)
- [Supported Languages](#supported-languages)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Feature | Description |
|---|---|
| 🧠 **AI Analysis** | GPT-4o reviews code for context-aware, logic-level vulnerabilities and provides tailored fix recommendations |
| ⚡ **Static Analysis** | Instant regex-based SAST scanning for 11+ common vulnerability patterns |
| 🌍 **Multi-Language** | Python, JavaScript, TypeScript, Java, PHP, Ruby, Go, C/C++, C#, SQL and more |
| 📋 **CWE Mapping** | Every finding is mapped to a [CWE](https://cwe.mitre.org/) identifier |
| 🖥️ **Web UI** | Clean dark-themed interface — paste code or upload a file |
| 🔌 **REST API** | JSON API for CI/CD integration (`POST /api/analyze`) |
| 💻 **CLI** | Command-line tool for local scanning with colour output and JSON export |
| 🚫 **Zero False-Positives Guarantee** | Static rules are deliberately conservative |
| 🐳 **Docker Support** | Single-command deployment with Docker |

---

## Screenshots

### Home Page
![Home page with code input form](https://i.imgur.com/placeholder-home.png)

### Results Page
![Analysis results showing findings by severity](https://i.imgur.com/placeholder-results.png)

> _Note: Run the app locally (`python app.py`) to see the live UI._

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   User Interfaces                   │
│  ┌──────────────┐  ┌────────────┐  ┌─────────────┐ │
│  │   Web UI     │  │  REST API  │  │     CLI     │ │
│  │ (Flask/HTML) │  │ /api/analyze│  │  cli.py    │ │
│  └──────┬───────┘  └─────┬──────┘  └──────┬──────┘ │
└─────────┼────────────────┼────────────────┼─────────┘
          │                │                │
          └────────────────▼────────────────┘
                      analyzer.py
                   ┌──────────────┐
                   │   analyse()  │
                   └──────┬───────┘
          ┌────────────────┴────────────────┐
          ▼                                 ▼
   Static Analysis                    AI Analysis
   (regex SAST rules)             (OpenAI GPT-4o API)
          │                                 │
          └────────────────┬────────────────┘
                           ▼
                   Merged & Deduplicated
                     AnalysisResult
```

---

## Detected Vulnerabilities

### Static Analysis Rules

| ID | Vulnerability | Severity | CWE |
|---|---|---|---|
| SQL_INJECTION | SQL Injection via string concatenation | 🔴 CRITICAL | CWE-89 |
| COMMAND_INJECTION | OS command injection | 🔴 CRITICAL | CWE-78 |
| HARDCODED_PASSWORD | Hardcoded password in source | 🟠 HIGH | CWE-798 |
| HARDCODED_SECRET_KEY | Hardcoded API key / token | 🟠 HIGH | CWE-312 |
| XSS_INNERHTML | Cross-Site Scripting via innerHTML | 🟠 HIGH | CWE-79 |
| EVAL_USAGE | Use of `eval()` | 🟠 HIGH | CWE-95 |
| PATH_TRAVERSAL | Path traversal via user input | 🟠 HIGH | CWE-22 |
| PICKLE_LOAD | Insecure deserialization (pickle) | 🟠 HIGH | CWE-502 |
| WEAK_HASH_MD5 | Weak hash algorithm (MD5) | 🟡 MEDIUM | CWE-327 |
| WEAK_HASH_SHA1 | Weak hash algorithm (SHA-1) | 🟡 MEDIUM | CWE-327 |
| DEBUG_ENABLED | Debug mode enabled in production | 🟡 MEDIUM | CWE-215 |

### AI Analysis (GPT-4o)

When an OpenAI API key is configured, GPT-4o performs a deep review and can additionally detect:

- Business logic flaws
- Insecure direct object references (IDOR)
- Race conditions
- Improper error handling exposing sensitive data
- Missing authentication or authorisation checks
- Cryptographic misuse beyond simple pattern matching
- … and any other context-dependent vulnerability

---

## Project Structure

```
AI-Powered-Secure-Code-Analysis-Tool/
├── app.py                  # Flask web application
├── analyzer.py             # Core analysis engine (static + AI)
├── cli.py                  # Command-line interface
├── config.py               # Configuration & constants
├── requirements.txt        # Python dependencies
├── Dockerfile              # Docker image definition
├── .env.example            # Environment variable template
├── .gitignore
├── templates/
│   ├── index.html          # Home / input page
│   └── result.html         # Analysis results page
├── static/
│   ├── css/style.css       # Stylesheet
│   └── js/main.js          # Frontend JavaScript
└── tests/
    ├── test_analyzer.py    # Unit tests for the analysis engine
    └── test_app.py         # Integration tests for Flask routes
```

---

## Getting Started

### Prerequisites

- Python **3.10** or higher
- An [OpenAI API key](https://platform.openai.com/api-keys) _(optional – static analysis works without it)_

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Himanshumathankar/AI-Powered-Secure-Code-Analysis-Tool.git
cd AI-Powered-Secure-Code-Analysis-Tool

# 2. Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Configuration

Copy the example environment file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env`:

```dotenv
# Required for AI analysis (leave blank to use static analysis only)
OPENAI_API_KEY=sk-...

# Flask session secret – change this to a random string in production
FLASK_SECRET_KEY=change-me-in-production

# development | production
FLASK_ENV=development

# Maximum uploaded file size in megabytes
MAX_FILE_SIZE_MB=5
```

### Running the Web App

```bash
python app.py
```

Open your browser at **http://localhost:5000**.

You can:
- **Paste** source code into the textarea and select the language
- **Upload** a source file directly
- View colour-coded findings sorted by severity

### Using the CLI

```bash
# Analyse a file
python cli.py path/to/your/code.py

# Analyse an inline snippet
python cli.py --code "import os; os.system('ls ' + user_input)"

# Pipe from stdin
cat vulnerable.js | python cli.py -

# Export results as JSON
python cli.py path/to/code.py --json

# Specify a virtual filename to control language detection
python cli.py --code "eval(req.body.expr)" --filename app.js

# Disable colour output (useful for CI logs)
python cli.py code.py --no-colour
```

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | No issues found |
| 1 | MEDIUM or LOW issues found |
| 2 | CRITICAL or HIGH issues found |

### REST API

The JSON API is ideal for integrating into CI/CD pipelines.

**Endpoint:** `POST /api/analyze`

**Request body:**

```json
{
  "code": "<source code string>",
  "filename": "optional_filename.py"
}
```

**Response:**

```json
{
  "language": "Python",
  "overall_risk": "CRITICAL",
  "total": 2,
  "ai_available": true,
  "summary": "The code contains a SQL injection vulnerability...",
  "counts": {
    "CRITICAL": 1,
    "HIGH": 1,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0
  },
  "vulnerabilities": [
    {
      "title": "Potential SQL Injection",
      "severity": "CRITICAL",
      "line": 3,
      "description": "User-supplied data appears to be concatenated...",
      "recommendation": "Use parameterised queries or prepared statements.",
      "cwe": "CWE-89",
      "source": "static"
    }
  ]
}
```

**Example with curl:**

```bash
curl -s -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"hunter2\"", "filename": "config.py"}' \
  | python -m json.tool
```

**Example GitHub Actions integration:**

```yaml
- name: Security Scan
  run: |
    RESULT=$(curl -sf -X POST $SCAN_URL/api/analyze \
      -H "Content-Type: application/json" \
      -d "{\"code\": \"$(cat src/main.py | python -c 'import json,sys; print(json.dumps(sys.stdin.read()))')\", \"filename\": \"main.py\"}")
    echo "$RESULT" | python -m json.tool
    RISK=$(echo "$RESULT" | python -c "import json,sys; print(json.load(sys.stdin)['overall_risk'])")
    [ "$RISK" != "CRITICAL" ] && [ "$RISK" != "HIGH" ] || exit 1
```

---

## Docker

```bash
# Build the image
docker build -t secure-code-analyzer .

# Run with your OpenAI key
docker run -p 5000:5000 \
  -e OPENAI_API_KEY=sk-... \
  -e FLASK_SECRET_KEY=mysecretkey \
  secure-code-analyzer
```

Open **http://localhost:5000** in your browser.

---

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run only analyser unit tests
python -m pytest tests/test_analyzer.py -v

# Run only Flask integration tests
python -m pytest tests/test_app.py -v
```

The test suite covers:
- Language detection (extension + shebang)
- All 11 static SAST rules (true positives)
- Negative tests (no false positives on clean code)
- `analyse()` integration (severity calculation, deduplication)
- All Flask routes (web UI + JSON API)

---

## How It Works

```
  1. User submits code (web form / API / CLI)
           │
           ▼
  2. detect_language()
     └── From file extension or shebang line
           │
           ▼
  3. run_static_analysis()
     └── Applies 11 regex-based SAST rules
     └── Returns list[Vulnerability]
           │
           ▼
  4. run_ai_analysis()   (if OPENAI_API_KEY is set)
     └── Sends code + language to GPT-4o
     └── Parses structured JSON response
     └── Returns list[Vulnerability] + summary
           │
           ▼
  5. Merge & deduplicate
     └── Combines static + AI findings
     └── Removes (title, line) duplicates
           │
           ▼
  6. Compute overall_risk
     └── Highest severity of all findings
           │
           ▼
  7. Return AnalysisResult
     └── Rendered as HTML (web) or JSON (API/CLI)
```

---

## Supported Languages

| Language | Extension | Static Rules | AI Analysis |
|---|---|---|---|
| Python | `.py` | ✅ | ✅ |
| JavaScript | `.js` | ✅ | ✅ |
| TypeScript | `.ts` | ✅ | ✅ |
| Java | `.java` | ✅ | ✅ |
| PHP | `.php` | ✅ | ✅ |
| Ruby | `.rb` | ✅ | ✅ |
| Go | `.go` | ✅ | ✅ |
| C | `.c` | ✅ | ✅ |
| C++ | `.cpp` | ✅ | ✅ |
| C# | `.cs` | ✅ | ✅ |
| SQL | `.sql` | ✅ | ✅ |
| Swift | `.swift` | ✅ | ✅ |
| Kotlin | `.kt` | ✅ | ✅ |
| Rust | `.rs` | ✅ | ✅ |
| HTML | `.html` | ✅ | ✅ |

---

## Contributing

Contributions are welcome! Here's how to add a new static analysis rule:

1. Open `analyzer.py`
2. Add a new entry to the `STATIC_RULES` list:

```python
{
    "id": "MY_RULE",
    "title": "Short descriptive title",
    "pattern": re.compile(r"your_regex_here", re.IGNORECASE),
    "severity": config.SEVERITY_HIGH,
    "description": "What the vulnerability is and why it matters.",
    "recommendation": "How to fix it.",
    "cwe": "CWE-XXX",
},
```

3. Add a test in `tests/test_analyzer.py`
4. Open a pull request

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  Built with ❤️ by <a href="https://github.com/Himanshumathankar">Himanshumathankar</a>
</p>
