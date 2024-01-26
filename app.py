from flask import Flask, request, jsonify, render_template
from instagrapi import Client

app = Flask(__name__)


@app.route('/')
def home():
    return render_template('index.html')


def ig_login(username, password):
    client = Client()
    client.login(username, password)
    return client


@app.route("/post", methods=["POST"])
def post_image():
    username = request.form['username']
    password = request.form['password']
    photo_path = request.form['photo_path']
    caption = request.form['caption']

    client = ig_login(username, password)
    client.photo_upload(photo_path, caption)

    return "Image Posted!"


@app.route("/like", methods=["POST"])
def like_post():
    username = request.form['username']
    password = request.form['password']
    media_id = request.form['media_id']

    client = ig_login(username, password)
    client.media_like(media_id)

    return "Post Liked!"


@app.route("/comment", methods=["POST"])
def comment_ig():
    username = request.form['username']
    password = request.form['password']
    media_id = request.form['media_id']
    comment = request.form['comment']

    client = ig_login(username, password)
    client.media_comment(media_id, comment)

    return "Commented!"


if __name__ == '__main__':
    app.run(debug=True)