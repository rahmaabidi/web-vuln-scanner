import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_site(base_url, limit=10):
    visited = set()
    to_visit = [base_url]
    domain = urlparse(base_url).netloc
    pages = []

    while to_visit and len(pages) < limit:
        url = to_visit.pop(0)
        if url in visited:
            continue
        try:
            response = requests.get(url, timeout=5)
            pages.append(url)
            visited.add(url)

            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link['href']
                full_url = urljoin(url, href)
                parsed_url = urlparse(full_url)
                # Only crawl links within the same domain
                if parsed_url.netloc == domain and full_url not in visited:
                    to_visit.append(full_url)
        except requests.RequestException:
            # Ignore errors, continue crawling others
            continue

    return pages
