
import requests


def analyze_cookies(url):
        try:
              response = requests.get(url)
              cookies =response.cookies 
              report=""
              for cookie in cookies:
                report+=f"cookie: {cookie.name}\n"
                report+=f" -secure:{cookie.secure}\n"
                report+=f"HttpOnly: {'HttpOnly' in cookie._rest}\n"
                report+=f" -SameSite:{cookie._rest.get('samesite','Not Set')}\n"
              return report if report else "No cookies found."
        except Exception as e:
             return f"EROOR ANALYZING COOKIES :{str(e)}"
