from flask import Flask, request, jsonify, flash, render_template, redirect, url_for, session, abort
from instagrapi import Client
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from secret import API_KEY, SECRET_KEY, MAIL_DEFAULT_SENDER, MAIL_PASSWORD, MAIL_PORT, MAIL_SERVER, MAIL_USERNAME
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_migrate import Migrate
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect
from openai import OpenAI, BadRequestError
import requests
import json
import random
import uuid
import os
import sched
import time
import threading
import logging

app = Flask(__name__, template_folder="templates")
csrf = CSRFProtect(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db?check_same_thread=False"
db = SQLAlchemy(app)
migrate = Migrate(app, db)

app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = MAIL_DEFAULT_SENDER

mail = Mail(app)

ai_client = OpenAI(api_key=API_KEY)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(120), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6))
    verification_code_expiry = db.Column(db.DateTime)

    def set_pass(self, password):
        self.password_hash = generate_password_hash(password)

    def check_pass(self, password):
        return check_password_hash(self.password_hash, password)


app.secret_key = SECRET_KEY

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

s = URLSafeTimedSerializer(app.secret_key)


def send_verif_email(user_email):
    user = User.query.filter_by(email=user_email).first()
    if user:
        verification_code = "".join([str(random.randint(0, 9)) for _ in range(6)])
        user.verification_code = verification_code
        user.verification_code_expiry = datetime.utcnow() + timedelta(minutes=10)

        db.session.commit()
        message = Message("Email Verification", recipients=[user.email])
        message.body = f"Your code is: {verification_code}"
        mail.send(message)


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$',
               message="Your password must be at least 8 characters long and include a letter, number, and special "
                       "character.")
    ])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(),
                                                                     EqualTo("password",
                                                                             message="Passwords Must Match")])
    email = StringField("Email", validators=[DataRequired(), Email()])
    verif_code = StringField("Code", validators=[DataRequired()])
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError("Username Taken. Please choose another one.")


logging.basicConfig(filename='app.log',
                    filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    level=logging.INFO)

scheduler = sched.scheduler(time.time, time.sleep)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/')
def home():
    logged_in = is_user_logged_in()
    return render_template("index.html", logged_in=logged_in)


@app.route('/send-verification-email', methods=['POST'])
def send_verification_email():
    data = json.loads(request.data)
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'message': 'An account with this email already exists.'}), 400

    verification_code = "".join([str(random.randint(0, 9)) for _ in range(6)])
    expiry = datetime.utcnow() + timedelta(minutes=10)

    session['verification_code'] = verification_code
    session['verification_email'] = email
    session['verification_expiry'] = expiry.strftime("%Y-%m-%d %H:%M:%S")

    message = Message("Email Verification", recipients=[email])
    message.body = f"Your verification code is: {verification_code}"
    mail.send(message)
    return jsonify({'message': 'Verification email sent. Please check your inbox.'})


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if (session.get('verification_code') == form.verif_code.data and
                session.get('verification_email') == form.email.data and
                datetime.utcnow() <= datetime.strptime(session.get('verification_expiry'), "%Y-%m-%d %H:%M:%S")):
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, password_hash=hashed_password, email=form.email.data,
                            email_verified=True)
            db.session.add(new_user)
            db.session.commit()
            flash("You have been successfully registered and verified. Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid or expired verification code.", "danger")
    return render_template("register.html", title="Register", form=form)


class LoginForm(FlaskForm):
    username = StringField("Username or Email", validators=[DataRequired(), Length(min=2, max=24)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_pass(form.password.data):
            if user.email_verified:
                session["user_id"] = user.id
                return redirect(url_for("home"))
            elif not user.email_verified:
                flash("Email has not been verified. Please verify your email.")
            else:
                flash("Unknown Error Encountered.")
        else:
            flash("Login Failed. Check username and password", "danger")
    return render_template("login.html", title="Login", form=form)


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Successfully Logged Out.", "info")
    return redirect(url_for("login"))


class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Request Password Reset")


def send_reset_email(user):
    token = s.dumps(user.email, salt='reset-password')
    msg = Message('Password Reset Request', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[user.email])
    reset_url = url_for('reset_token', token=token, _external=True)
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash('If an account with that email exists, a password reset email has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgotpassword.html', title='Reset Password', form=form)


class ResetPasswordForm(FlaskForm):
    password = PasswordField("Password", validators=[
        DataRequired(),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$',
               message="Your password must be at least 8 characters long and include a letter, number, and special "
                       "character.")
    ])
    confirm_new_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    logging.debug(f'Received token for password reset: {token}')
    try:
        email = s.loads(token, salt='reset-password', max_age=1800)
    except BadSignature:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('forgot_password'))
    user = User.query.filter_by(email=email).first()
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_pass(form.password.data)
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('resetpassword.html', title='Reset Password', form=form, token=token)


def is_user_logged_in():
    return 'user_id' in session


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
    try:
        client = ig_login(username, password)
        client.photo_upload(file_path, caption)
    except EnvironmentError:
        print("Error. Image did not post")
        logging.error("Image post failed.")


def exec_like(username, password, media_id):
    try:
        client = ig_login(username, password)
        client.media_like(media_id)
    except EnvironmentError:
        print("Error. Post was not liked.")
        logging.error("Like post failed.")


def exec_comment(username, password, media_id, comment):
    try:
        client = ig_login(username, password)
        client.media_comment(media_id, comment)
    except EnvironmentError:
        print("Error. Post was not liked")
        logging.error("Comment on post failed.")


def download_image(image_url, file_name):
    response = requests.get(image_url)
    if response.status_code == 200:
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_name)
        with open(file_path, 'wb') as f:
            f.write(response.content)
        return file_path
    else:
        raise Exception(f"Failed to download image. Status code: {response.status_code}")


@app.route("/post", methods=["POST"])
def post_image():
    csrf.protect()
    username = request.form['username']
    password = request.form['password']
    caption = request.form['caption']
    ai_prompt = request.form["ai_prompt"]
    scheduled_time = request.form.get("schedule_time")

    if ai_prompt:
        try:
            response = ai_client.images.generate(
                model="dall-e-3",
                prompt=ai_prompt,
                size="1024x1024",
                quality="standard",
                n=1,
            )
            image_url = response.data[0].url
            unique_filename = secure_filename(f"{uuid.uuid4()}_generated.png")
            file_path = download_image(image_url, unique_filename)
        except BadRequestError as e:
            app.logger.error(f"OpenAI API error: {e}")
            flash("An error occurred with the image generation service. Please try again later.", "error")
        except EnvironmentError:
            flash("Error generating AI Image. Please try again later.")
    else:
        photo = request.files["photo"]
        unique_filename = secure_filename(f"{uuid.uuid4()}_{photo.filename}")
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)
        photo.save(file_path)

    if scheduled_time:
        scheduled_time = datetime.strptime(scheduled_time, "%Y-%m-%dT%H:%M")
        post_delay = (scheduled_time - datetime.now()).total_seconds()
        if post_delay > 0:
            sched_item(post_delay, exec_post, username, password, file_path, caption)
            timestamps = session.get("scheduled_posts_timestamps", [])
            timestamps.append(datetime.utcnow())
            session["scheduled_posts_timestamps"] = timestamps
            return "Successfully Scheduled."
        else:
            exec_post(username, password, file_path, caption)
            return "Scheduled time has passed. Image Posting Now."
    else:
        exec_post(username, password, file_path, caption)
        return "Successfully Posted"


@app.route("/like", methods=["POST"])
def like_post():
    csrf.protect()
    username = request.form['username']
    password = request.form['password']
    media_id = request.form['media_id']
    scheduled_time = request.form.get("schedule_time_like")

    if scheduled_time:
        scheduled_time = datetime.strptime(scheduled_time, "%Y-%m-%dT%H:%M")
        like_delay = (scheduled_time - datetime.now()).total_seconds()
        if like_delay > 0:
            sched_item(like_delay, exec_like, username, password, media_id)
            return "Successfully Scheduled."
        else:
            exec_like(username, password, media_id)
            return "Scheduled time has passed. Liking Post Now."
    else:
        exec_like(username, password, media_id)
        return "Successfully Liked"


@app.route("/comment", methods=["POST"])
def comment_ig():
    csrf.protect()
    username = request.form['username']
    password = request.form['password']
    media_id = request.form['media_id']
    comment = request.form['comment']
    scheduled_time = request.form.get("schedule_time_com")

    if scheduled_time:
        scheduled_time = datetime.strptime(scheduled_time, "%Y-%m-%dT%H:%M")
        comment_delay = (scheduled_time - datetime.now()).total_seconds()
        if comment_delay > 0:
            sched_item(comment_delay, exec_comment, username, password, media_id, comment)
            return "Successfully Scheduled."
        else:
            exec_comment(username, password, media_id, comment)
            return "Scheduled time has passed. Commenting on post now."
    else:
        exec_comment(username, password, media_id, comment)
        return "Successfully Commented."


def rate_limit():
    timestamps = session.get("scheduled_posts_timestamps", [])
    prev_hour = datetime.utcnow() - timedelta(hours=1)
    timestamps_prev_hour = [ts.replace(tzinfo=None) for ts in timestamps if ts.replace(tzinfo=None) > prev_hour]
    session["scheduled_posts_timestamps"] = timestamps_prev_hour
    return len(timestamps_prev_hour) >= 50


@app.before_request
def check_rate_limit():
    if request.endpoint in ["post_image", "like_post", "comment_ig"]:
        if rate_limit():
            abort(429, description="You have reached 50 scheduled posts in one hour. No more posts may be scheduled.")


@app.cli.command("delete-users")
def delete_users():
    try:
        num_deleted = User.query.delete()
        db.session.commit()
        print(f"Deleted {num_deleted} users.")
    except Exception as e:
        db.session.rollback()
        print(f"An error occurred: {e}")

# if __name__ == '__main__':
# app.run(debug=True)
