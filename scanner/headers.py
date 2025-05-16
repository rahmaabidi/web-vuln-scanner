import requests
from requests.exceptions import SSLError, RequestException

def analyze_headers(url):
    try:
        response = requests.get(url, timeout=10, verify=True)
        headers = dict(response.headers)

        # Build a readable string report from headers
        report_lines = []
        for key, value in headers.items():
            report_lines.append(f"{key}: {value}")

        # Check important security headers presence
        important_headers = {
            "Content-Security-Policy": "Prevents XSS and data injection attacks",
            "X-Frame-Options": "Prevents clickjacking",
            "Strict-Transport-Security": "Enforces HTTPS",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "Referrer-Policy": "Controls referrer info sent",
            "Permissions-Policy": "Restricts APIs and features",
        }

        report_lines.append("\nSecurity Headers Check:")
        for hdr, desc in important_headers.items():
            if hdr in headers:
                report_lines.append(f"✔ {hdr} is present — {desc}")
            else:
                report_lines.append(f"❌ {hdr} is missing — {desc}")

        return "\n".join(report_lines)

    except SSLError:
        return {
            "error": "SSL Error: Could not fetch headers due to SSL certificate issues.",
            "note": "The SSL certificate may be self-signed or not trusted."
        }
    except RequestException as e:
        return {
            "error": f"Request error: {str(e)}"
        }
