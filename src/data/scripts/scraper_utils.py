import requests
from bs4 import BeautifulSoup

def scrape(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.get_text(separator='\n', strip=True)
    except Exception as e:
        print(f"[!] Error scraping {url}: {e}")
        return ""
