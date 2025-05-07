# Web Vulnerability Scanner (mini-ZAP)

A basic Python tool for scanning websites for common security vulnerabilities:

- Missing or insecure HTTP headers
- Insecure cookie attributes
- Reflected Cross-Site Scripting (XSS)

## Usage

```bash
pip install -r requirements.txt
python main.py --url https://example.com
```

## Output
Scan results are saved in `reports/scan_report.txt`

---

This project is intended for educational and ethical testing purposes only.


# --- File: .gitignore ---
__pycache__/
*.pyc
reports/
venv/
