import requests
from requests.exceptions import SSLError, RequestException

def analyze_cookies(url):
    try:
        response = requests.get(url, timeout=10, verify=True)
        cookies = response.cookies
        if not cookies:
            return "✅ No cookies found."

        report = ""
        for cookie in cookies:
            report += f"Cookie: {cookie.name}\n"
            report += f" - Secure: {cookie.secure}\n"
            report += f" - HttpOnly: {'HttpOnly' in cookie._rest}\n"
            report += f" - SameSite: {cookie._rest.get('samesite', 'Not Set')}\n"
        return report

    except SSLError:
        return "⚠️ SSL Error: The site's SSL certificate is invalid or untrusted. Cookie analysis skipped."

    except RequestException:
        return "⚠️ Connection Error: Unable to reach the website. Cookie analysis skipped."

    except Exception as e:
        return f"⚠️ Error analyzing cookies: {str(e)}"
