from flask import Flask, request, jsonify, render_template
from instagrapi import Client
import os
import datetime
import sched
import time
import threading

scheduler = sched.scheduler(time.time, time.sleep)

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


def sched_item(delay, function, *args):
    def exec_task():
        scheduler.enter(delay, 1, function, args)
        scheduler.run()

    threading.Thread(target=exec_task).start()


def exec_post(username, password, file_path, caption):
    client = ig_login(username, password)
    client.photo_upload(file_path, caption)


@app.route("/post", methods=["POST"])
def post_image():
    username = request.form['username']
    password = request.form['password']
    caption = request.form['caption']
    photo = request.files["photo"]
    scheduled_time = request.form.get("schedule_time")

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], photo.filename)
    photo.save(file_path)

    if scheduled_time:
        scheduled_time = datetime.datetime.strptime(scheduled_time, "%Y-%m-%dT%H:%M")
        post_delay = (scheduled_time - datetime.datetime.now()).total_seconds()
        if post_delay > 0:
            sched_item(post_delay, exec_post, username, password, file_path, caption)
            return "Successfully Scheduled."
        else:
            exec_post(username, password, file_path, caption)
            return "Scheduled time has passed. Image Posting Now."
    else:
        exec_post(username, password, file_path, caption)
        return "Successfully Posted"


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
