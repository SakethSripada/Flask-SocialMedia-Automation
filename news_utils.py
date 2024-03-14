from newsapi import NewsApiClient
from secret import NEWS_API_KEY
from collections import Counter
from PIL import Image, ImageDraw, ImageFont
import textwrap
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
    words = [token.text.lower() for token in doc if token.pos_ in ["NOUN"]]
    word_freq = Counter(words)
    most_common_words = word_freq.most_common(1)
    return [word for word, freq in most_common_words]


def get_first_n_words(text, number_of_words):
    words = text.split()
    first_n_words = words[:number_of_words]
    return ' '.join(first_n_words)


def add_text_to_image(image_path, text, position, font_size=65, font_color=(0, 0, 0), border_color=(255, 255, 255),
                      border_width=2):
    image = Image.open(image_path)
    draw = ImageDraw.Draw(image)
    image_width, image_height = image.size

    try:
        font = ImageFont.truetype("arial.ttf", font_size)
    except IOError:
        font = ImageFont.load_default()

    avg_char_width = sum(font.getsize(char)[0] for char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz') / 52
    wrap_width = int(image_width / avg_char_width)

    lines = textwrap.wrap(text, width=wrap_width)

    text_height = sum([font.getsize(line)[1] for line in lines])

    y_text = image_height - text_height - position[1]
    for line in lines:
        line_width, line_height = font.getsize(line)
        x_text = (image_width - line_width) / 2

        for dx, dy in [(i, j) for i in range(-border_width, border_width + 1) for j in
                       range(-border_width, border_width + 1)]:
            draw.text((x_text + dx, y_text + dy), line, font=font, fill=border_color)

        draw.text((x_text, y_text), line, font=font, fill=font_color)
        y_text += line_height

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
    image.save(temp_file.name)
    return temp_file.name
