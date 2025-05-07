from bs4 import BeautifulSoup
import requests
def test_xss(url):
    try :
        payload="<script>alert('XSS')</script>"
        test_url=f"{url}?q={payload}"
        response = requests.get(test_url)
        soup = BeautifulSoup(response.text,'html.parser')

        if payload in soup.text :
           return"[!] potential reflected  XSS vulnerability detected."
        return"[+] NO REFLECTED XSS vulnerability detected"
    except Exception as e :
        return f"Error during XSS testing :{str(e)}"
    

