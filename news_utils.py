from newsapi import NewsApiClient
from secret import NEWS_API_KEY
from collections import Counter
from PIL import Image, ImageDraw, ImageFont
import requests
import tempfile
import spacy
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


def download_image_to_draw(image_url):
    response = requests.get(image_url)
    if response.status_code == 200:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png', mode='wb+')
        temp_file.write(response.content)
        temp_file.close()
        return temp_file.name
    else:
        raise Exception(f"Failed to download image. Status code: {response.status_code}")


def add_text_to_image(image_path, text, position, font_size=30, font_color=(255, 255, 255)):
    image = Image.open(image_path)
    draw = ImageDraw.Draw(image)

    try:
        font = ImageFont.truetype("arial.ttf", font_size)
    except IOError:
        font = ImageFont.load_default()

    draw.text(position, text, font_color, font=font)

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png', mode='wb+')
    image.save(temp_file.name)
    return temp_file.name
