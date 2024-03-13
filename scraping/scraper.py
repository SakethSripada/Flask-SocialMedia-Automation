from bs4 import BeautifulSoup
import requests


def scrape(url):
    response = requests.get(url)
    if response.status_code == 200:
        return BeautifulSoup(response.content, 'html.parser')
    else:
        response.raise_for_status()


def scrape_table(url):
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        tables = soup.find_all('table')
        result = []
        for table in tables:
            headers = [th.get_text().strip() for th in table.find_all('th')]
            rows = table.find_all('tr')
            table_data = []
            for row in rows:
                cells = row.find_all('td')
                if cells:
                    data = {headers[i]: cell.get_text().strip() for i, cell in enumerate(cells)}
                    table_data.append(data)
            result.append(table_data)
        return result
    else:
        response.raise_for_status()


def scrape_images(url):
    soup = scrape(url)
    images = [{'alt': img.get('alt', ''), 'src': img.get('src', '')} for img in soup.find_all('img')]
    return images


def extract_links(url):
    soup = scrape(url)
    links = [{'text': a.text, 'href': a.get('href', '')} for a in soup.find_all('a')]
    return links


def extract_metadata(url):
    soup = scrape(url)
    metadata = {meta.get('name', ''): meta.get('content', '') for meta in soup.find_all('meta')}
    return metadata
