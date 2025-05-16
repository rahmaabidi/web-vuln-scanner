import requests
from requests.exceptions import SSLError, RequestException

def test_xss(url):
    """
    Tests for reflected XSS vulnerabilities by injecting a payload into a query parameter.
    Returns a user-friendly error message on SSL or connection issues.
    """
    try:
        payload = "<script>alert('xss')</script>"
        target = f"{url}?q={payload}"
        resp = requests.get(target, timeout=10, verify=True)

        if payload in resp.text:
            return "⚠️ Potential XSS vulnerability detected!"
        else:
            return "✅ No reflected XSS detected."
    
    except SSLError:
        return {
            "error": "SSL Error: The site has an untrusted or invalid certificate.",
            "note": "XSS scan was skipped because the SSL certificate could not be verified."
        }

    except RequestException:
        return {
            "error": "Connection Error: Unable to connect to the target site.",
            "note": "XSS scan was skipped because the site may be offline or unreachable."
        }

    except Exception as e:
        return {
            "error": f"Unexpected Error: {str(e)}"
        }
