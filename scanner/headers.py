import requests 
 #list of recommended security headers 
security_headers = [
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
def analyze_headers(url):
    try:

        response = requests.get(url)
        headers = response.headers 
        report=""
        for header in security_headers:
            if header in headers :
                report +=f"[+]{header}:{header[header]}\n"
            else :
                report +=f"[-]{header} is missing\n"
        return report 
    except Exception as e :
        return f"ERROR ANALYZING HEADERS:{str(e)}"