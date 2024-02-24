from newsapi import NewsApiClient
from secret import NEWS_API_KEY
import spacy
from collections import Counter
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


def get_main_entities(headline):
    nlp = spacy.load("en_core_web_sm")
    doc = nlp(headline)
    words = [token.text.lower() for token in doc if token.pos_ in ["NOUN", "PROPN", "ORG", "GPE"]]
    word_freq = Counter(words)
    most_common_words = word_freq.most_common(2)
    return [word for word, freq in most_common_words]
