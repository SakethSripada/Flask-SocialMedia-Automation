from scraper import scrape


def get_text(url):
    soup = scrape(url)
    paragraphs = soup.find_all('p')
    return '\n'.join([paragraph.get_text().strip() for paragraph in paragraphs])
