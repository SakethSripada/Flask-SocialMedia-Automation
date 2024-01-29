from flask import Flask, request, jsonify, render_template
from instagrapi import Client
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


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
    caption = request.form['caption']
    photo = request.files["photo"]

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], photo.filename)
    photo.save(file_path)
    client = ig_login(username, password)
    client.photo_upload(file_path, caption)

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
