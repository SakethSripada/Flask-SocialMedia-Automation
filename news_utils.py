from newsapi import NewsApiClient
from secret import NEWS_API_KEY


def get_top_headlines(country='us'):
    news_client = NewsApiClient(api_key=NEWS_API_KEY)
    try:
        top_headlines = news_client.get_top_headlines(country=country)
        return top_headlines
    except Exception as e:
        print(f"An error occurred while fetching top headlines: {e}")
        return None


def get_first_title(headlines):
    if headlines and 'articles' in headlines and headlines['articles']:
        first_title = headlines['articles'][0]['title']
        return first_title
    else:
        return "No headlines found."
