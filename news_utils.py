from newsapi import NewsApiClient
from secret import NEWS_API_KEY
import random


def get_top_headlines(country='us'):
    news_client = NewsApiClient(api_key=NEWS_API_KEY)
    try:
        top_headlines = news_client.get_top_headlines(country=country)
        return top_headlines
    except Exception as e:
        print(f"An error occurred while fetching top headlines: {e}")
        return None


def get_random_title(headlines):
    if headlines and 'articles' in headlines and headlines['articles']:
        random_article = random.choice(headlines['articles'])
        return random_article['title']
    else:
        return "No headlines found."
