from flask import Flask, request, jsonify, flash, render_template, redirect, url_for, session
from flask_limiter.util import get_remote_address
from instagrapi import Client
from flask_limiter import Limiter
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from secret import API_KEY, SECRET_KEY, MAIL_DEFAULT_SENDER, MAIL_PASSWORD, MAIL_PORT, MAIL_SERVER, MAIL_USERNAME
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature
from flask_migrate import Migrate
from datetime import datetime, timedelta, date
from flask_wtf.csrf import CSRFProtect
from openai import OpenAI, BadRequestError, RateLimitError
from flask.cli import with_appcontext
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore, JobLookupError
from news_utils import get_top_headlines, get_random_title, get_main_entities, add_text_to_image, get_first_n_words
import get_text
import smtplib
import secret
import base64
import hashlib
import click
import requests
import json
import random
import uuid
import os
import sched
import time
import threading
import logging

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# configurations
app = Flask(__name__, template_folder="templates")
csrf = CSRFProtect(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
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

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])


# DB model setup
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


class ScheduledTweet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tweet_content = db.Column(db.Text, nullable=False)
    scheduled_time = db.Column(db.DateTime, nullable=True)
    post_interval_seconds = db.Column(db.Integer, nullable=True)
    job_id = db.Column(db.String(255), unique=True, nullable=False)

    user = db.relationship('User', backref=db.backref('scheduled_tweets', lazy=True))


class ScheduledIGPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ai_prompt = db.Column(db.Text, nullable=True)
    caption = db.Column(db.Text, nullable=True)
    scheduled_time = db.Column(db.DateTime, nullable=True)
    post_interval_seconds = db.Column(db.Integer, nullable=True)
    job_id = db.Column(db.String(255), unique=True, nullable=False)

    user = db.relationship('User', backref=db.backref('scheduled_ig_posts', lazy=True))


class ScheduledEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email_content = db.Column(db.Text, nullable=False)
    recipients = db.Column(db.Text, nullable=False)
    scheduled_time = db.Column(db.DateTime, nullable=True)
    post_interval_seconds = db.Column(db.Integer, nullable=True)
    job_id = db.Column(db.String(255), unique=True, nullable=False)

    user = db.relationship('User', backref=db.backref('scheduled_emails', lazy=True))


app.config['SCHEDULER_JOBSTORES'] = {
    'default': SQLAlchemyJobStore(url=app.config["SQLALCHEMY_DATABASE_URI"])
}
twitter_scheduler = BackgroundScheduler(jobstores=app.config['SCHEDULER_JOBSTORES'])
twitter_scheduler.start()

app.secret_key = SECRET_KEY
# initialize app and create DB
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

s = URLSafeTimedSerializer(app.secret_key)


# function for sending verification emails
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


# form for registration
class RegisterForm(FlaskForm):
    # inputs that the user enters
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


# setting up logging
logging.basicConfig(filename='app.log',
                    filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    level=logging.INFO)
scheduler = sched.scheduler(time.time, time.sleep)  # instance of scheduler
# creating the folder for uploaded photos
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# home route
@app.route('/')
def home():
    logged_in = is_user_logged_in()
    return render_template("landing.html", logged_in=logged_in)


@app.route("/instagram_form")
def instagram_form():
    return render_template("instagram.html", logged_in='user_id' in session)


# route for sending of verification email
@limiter.limit("50/hour")
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
    try:
        mail.send(message)
        return jsonify({'message': 'Verification email sent. Please check your inbox.'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# route for account registration
@limiter.limit("50/hour")
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # check for verification code, email, and code expiry time
        if (session.get('verification_code') == form.verif_code.data and
                session.get('verification_email') == form.email.data and
                datetime.utcnow() <= datetime.strptime(session.get('verification_expiry'), "%Y-%m-%d %H:%M:%S")):
            hashed_password = generate_password_hash(form.password.data)
            # new instance of user created and added to DB
            new_user = User(username=form.username.data, password_hash=hashed_password, email=form.email.data,
                            email_verified=True)
            db.session.add(new_user)
            db.session.commit()
            flash("You have been successfully registered and verified. Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid or expired verification code.", "danger")
    return render_template("register.html", title="Register", form=form)


# form to log in
class LoginForm(FlaskForm):
    username = StringField("Username or Email", validators=[DataRequired(), Length(min=2, max=24)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


# route for logging in
@limiter.limit("50/hour")
@app.route("/login", methods=["GET", "POST"])
def login():
    # if user is already logged in, head to homepage
    if "user_id" in session:
        return redirect(url_for("home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()  # query for the user
        # check if the username exists, if the password hashes match, and if the user's email is verified
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


# route for log out
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Successfully Logged Out.", "info")
    return redirect(url_for("login"))


# form for forgot password
class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Request Password Reset")


# function to send the reset password email
@limiter.limit("50/hour")
def send_reset_email(user):
    # token generated based on user email, creates a unique token ONLY valid for resetting the password
    token = s.dumps(user.email, salt='reset-password')
    # email that is sent to the user
    msg = Message('Password Reset Request', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[user.email])
    reset_url = url_for('reset_token', token=token, _external=True)
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email and no changes will be made.
'''
    mail.send(msg)


# route executed upon submission of the forgot password form
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


# reset password form
class ResetPasswordForm(FlaskForm):
    password = PasswordField("Password", validators=[
        DataRequired(),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$',  # checks for below criteria
               message="Your password must be at least 8 characters long and include a letter, number, and special "
                       "character.")
    ])
    confirm_new_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


# reset password route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    logging.debug(f'Received token for password reset: {token}')
    try:
        email = s.loads(token, salt='reset-password', max_age=1800)  # deserializing token from earlier, if < 30 min old
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


# function to log in to the user's instagram
def ig_login(username, password):
    client = Client()
    client.login(username, password)
    return client


# function for scheduling an item
def sched_item(delay, function, *args):  # takes delay for when the action should occur, *args for flexibility
    def exec_task():  # scheduler receives priority and is started
        scheduler.enter(delay, 1, function, args)
        scheduler.run()

    threading.Thread(target=exec_task).start()  # new thread created so main program can continue running


# function for liking
def exec_like(username, password, media_id):  # necessary parameters for a like
    try:
        client = ig_login(username, password)
        client.media_like(media_id)
    except EnvironmentError:
        print("Error. Post was not liked.")
        logging.error("Like post failed.")


# function for commenting
def exec_comment(username, password, media_id, comment):  # necessary parameters for a comment
    try:
        client = ig_login(username, password)
        client.media_comment(media_id, comment)
    except EnvironmentError:
        print("Error. Post was not liked")
        logging.error("Comment on post failed.")


# function to download the AI generated image, so it can be uploaded
def download_image(image_url, file_name):
    response = requests.get(image_url)
    if response.status_code == 200:
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_name)
        with open(file_path, 'wb') as f:
            f.write(response.content)
        return file_path
    else:
        raise Exception(f"Failed to download image. Status code: {response.status_code}")


# function for posting
def exec_post(username, password, file_path, caption):  # necessary parameters for a post
    try:  # logging in to user account and performing action
        client = ig_login(username, password)
        client.photo_upload(file_path, caption)
    except EnvironmentError:
        print("Error. Image did not post")
        logging.error("Image post failed.")


def generate_ai_content(ai_prompt):
    if not ai_prompt:
        return None

    try:
        generated_tweet = ai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": ai_prompt},
            ],
            presence_penalty=0.6,
            frequency_penalty=0.6,
            temperature=0.7
        )
        tweet_content = generated_tweet.choices[0].message.content.strip()

        if len(tweet_content) > 250:
            tweet_content = tweet_content[:250].rstrip()

        return tweet_content
    except BadRequestError as e:
        app.logger.error(f"OpenAI API error: {e}")
        flash("An error occurred with the AI generation service. Please try again later.", "error")
    except RateLimitError:
        flash("OpenAI rate limit reached. Please try again later.")
    except EnvironmentError:
        flash("Error generating AI Tweet. Please try again later.")
    return None


instagram_scheduler = BackgroundScheduler()
instagram_scheduler.start()


def is_ip_blocked(client, username, password):
    ig_login(username, password)
    try:
        profile_info = client.account_info()
        return False
    except ConnectionRefusedError:
        return True


@limiter.limit("50/hour")
@app.route("/post", methods=["POST"])
def post_image():
    csrf.protect()
    username = request.form['username']
    password = request.form['password']
    caption = request.form['caption']
    caption_on_image = request.form['caption_on_image']
    ai_prompt = request.form.get("ai_prompt")
    scheduled_time = request.form.get("schedule_time")
    post_interval_hours = float(request.form.get("post_interval_hours") or 0)
    post_interval_seconds = post_interval_hours * 3600
    news_checkbox_checked = 'news_checkbox' in request.form
    user_id = session.get('user_id')
    client = ig_login(username, password)
    headlines = get_top_headlines(country="us")
    random_title = get_random_title(headlines)
    main_entity = get_main_entities(random_title)
    url_to_scrape = request.form['url_to_scrape']
    url_content = get_text.get_text(url_to_scrape)
    file_path = "/static/landing1.jpg"

    if news_checkbox_checked:
        ai_prompt = (main_entity[0] if main_entity else "News") + " " + random_title
        logging.info(f"AI Prompt: {ai_prompt}")
        caption = generate_ai_content(f"Pretend you are a news reporter who is in charge of writing short but "
                                      f"comprehensive captions for news headlines. Based on the following headline, "
                                      f" {random_title}generate such a caption. It should include no labels of any "
                                      f"sort, such as 'Headline' or 'Caption', and should SOLELY contain the content "
                                      f"of the caption you generated with no additional text, quotation marks, "
                                      f"or punctuations.")
    elif url_to_scrape:
        ai_prompt = get_first_n_words(url_content, 100)
        logging.info(f"AI Prompt: {ai_prompt}")
        caption = generate_ai_content(f"Generate a short Instagram caption for the following. It should be ONLY one"
                                      f"sentence: {ai_prompt}")
    try:
        if ai_prompt:
            if not is_ip_blocked(client, username, password):
                try:
                    response = ai_client.images.generate(
                        model="dall-e-2",
                        prompt=ai_prompt,
                        size="1024x1024",
                        quality="standard",
                        n=1,
                    )
                    image_url = response.data[0].url
                    temp_image_path = download_image(image_url, "to_draw_generated.png")
                    unique_filename = secure_filename(f"{uuid.uuid4()}_generated.png")
                    if news_checkbox_checked:
                        text_to_add = caption.upper()
                        position = (50, 50)
                        file_path = add_text_to_image(temp_image_path, text_to_add,
                                                      position)
                    elif not news_checkbox_checked:
                        file_path = download_image(image_url, unique_filename)
                    if not caption and not news_checkbox_checked and ai_prompt:
                        caption_ai_prompt = (f"Generate a short Instagram caption for the following. It should be "
                                             f"ONLY one"
                                             f"sentence: {ai_prompt}")
                        caption = generate_ai_content(caption_ai_prompt)

                except BadRequestError as e:
                    app.logger.error(f"OpenAI API error: {e}")
                    flash("An error occurred with the image generation service. Please try again later.", "error")
                except RateLimitError:
                    flash("OpenAI rate limit reached. Please try again later.")
                except EnvironmentError:
                    flash("Error generating AI Image. Please try again later.")
            elif is_ip_blocked(client, username, password):
                flash("Your IP has been blocked from using the AI image generation service. "
                      "Please try again later.", "error")
        elif caption_on_image:
            photo = request.files["photo"]
            text_to_add = caption_on_image.upper()
            position = (50, 50)
            file_path = add_text_to_image(photo, text_to_add, position)
        else:
            photo = request.files["photo"]
            unique_filename = secure_filename(f"{uuid.uuid4()}_{photo.filename}")
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)
            photo.save(file_path)
    except Exception as e:
        app.logger.error(f"An error occurred: {e}")
        flash("An error occurred with the image generation or upload. Please try again.", "error")
        return redirect(url_for('instagram_form'))

    job_id = f'{username}_{uuid.uuid4()}'
    if file_path:
        if scheduled_time:
            scheduled_time_dt = datetime.strptime(scheduled_time, "%Y-%m-%dT%H:%M")
            delay = (scheduled_time_dt - datetime.now()).total_seconds()
            if delay > 0:
                instagram_scheduler.add_job(exec_post, 'date', run_date=scheduled_time_dt,
                                            args=[username, password, file_path, caption], id=job_id)
                flash('Post scheduled successfully!', 'success')
            else:
                flash('Scheduled time has passed. Please choose a future time.', 'error')
        elif post_interval_hours:
            instagram_scheduler.add_job(exec_post, 'interval', seconds=post_interval_seconds,
                                        args=[username, password, file_path, caption], id=job_id,
                                        next_run_time=datetime.now())
            flash(f'Post scheduled to be posted every {post_interval_hours} hours!', 'success')
        else:
            exec_post(username, password, file_path, caption)
            flash('Post published successfully!', 'success')
    else:
        flash("An error occurred with the image generation or upload. Please try again.", "error")
    new_scheduled_ig = ScheduledIGPost(
        user_id=user_id,
        ai_prompt=ai_prompt if ai_prompt else None,
        caption=caption if caption else None,
        scheduled_time=scheduled_time_dt if scheduled_time else None,
        post_interval_seconds=post_interval_seconds if post_interval_hours else None,
        job_id=job_id
    )
    db.session.add(new_scheduled_ig)
    db.session.commit()

    return redirect(url_for('instagram_form'))


# route for liking posts, similar logic to posting route
@limiter.limit("50/hour")
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


# route for liking posts, similar logic to posting route
@limiter.limit("50/hour")
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


CALLBACK_URI = 'http://127.0.0.1:5000/auth/twitter/callback'


def pkce_transform(code_verifier):
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8').replace('=', '')
    return code_challenge


@limiter.limit("50/hour")
@app.route('/twitter/login')
def twitter_login():
    code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode('utf-8').replace('=', '')
    code_challenge = pkce_transform(code_verifier)
    session['code_verifier'] = code_verifier

    params = {
        'response_type': 'code',
        'client_id': secret.OAUTH_CLIENT_ID,
        'redirect_uri': CALLBACK_URI,
        'scope': 'tweet.read users.read follows.read follows.write tweet.write',
        'state': 'dfhufhdkfndne',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    url_params = "&".join([f"{key}={value}" for key, value in params.items()])
    authorization_url = f"https://twitter.com/i/oauth2/authorize?{url_params}"
    return redirect(authorization_url)


@app.route('/auth/twitter/callback')
def twitter_callback():
    code = request.args.get('code')
    code_verifier = session.pop('code_verifier', None)

    if code and code_verifier:
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic ' + base64.b64encode(
                f'{secret.OAUTH_CLIENT_ID}:{secret.OAUTH_CLIENT_SECRET}'.encode('utf-8')).decode('utf-8')
        }
        payload = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': secret.OAUTH_CLIENT_ID,
            'redirect_uri': CALLBACK_URI,
            'code_verifier': code_verifier
        }
        response = requests.post('https://api.twitter.com/2/oauth2/token', headers=headers, data=payload)

        if response.ok:
            token_data = response.json()
            session['access_token'] = token_data['access_token']
            return redirect(url_for('tweet_form'))
        else:
            return f"Error fetching access token: {response.text}", 400
    else:
        return "Authorization failed.", 400


def exec_post_tweet(access_token, ai_prompt=None, tweet_content=None, is_ai_generated=False):
    if is_ai_generated and ai_prompt:
        tweet_content = generate_ai_content(ai_prompt)
        if tweet_content is None:
            app.logger.error("Failed to generate tweet content.")
            return
    elif not tweet_content:
        app.logger.error("Tweet content is missing.")
        return

    headers = {'Authorization': f'Bearer {access_token}'}
    payload = {'text': tweet_content}
    response = requests.post('https://api.twitter.com/2/tweets', headers=headers, json=payload)

    if not response.ok:
        app.logger.error(f'Failed to post tweet: {response.status_code}, {response.text}')


twitter_scheduler = BackgroundScheduler()
twitter_scheduler.start()


@limiter.limit("50/hour")
@app.route('/post_tweet', methods=['POST'])
def post_tweet():
    ai_prompt = request.form.get("ai_prompt").strip()
    scheduled_time = request.form.get("schedule_time")
    post_interval_hours = float(request.form.get("post_interval_hours") or 0)
    access_token = session.get('access_token')
    post_interval_seconds = post_interval_hours * 3600
    user_id = session.get('user_id')
    news_checkbox_checked = 'news_checkbox' in request.form
    current_date = date.today()
    date_string = current_date.strftime("%Y-%m-%d")
    url_to_scrape = request.form['url_to_scrape']
    url_content = get_text.get_text(url_to_scrape)

    if not access_token or not user_id:
        flash('No access token found or user not logged in, please log in again.', 'error')
        return redirect(url_for('twitter_login'))

    if url_to_scrape:
        first_n_words = get_first_n_words(url_content, 100)
        ai_prompt = (f"Generate a short tweet based on the following 100 word excerpt. Do NOT exceed 200 characters "
                     f"when creating the short tweet. Do not wrap it in quotes either. {first_n_words}")
        logging.info(f"AI Prompt: {ai_prompt}")

    if ai_prompt:
        tweet_content = generate_ai_content(ai_prompt)
        logging.info(f"AI Generated Tweet: {tweet_content}")
        if not tweet_content:
            return redirect(url_for('tweet_form'))
    elif news_checkbox_checked:
        headlines = get_top_headlines(country="us")
        first_title = get_random_title(headlines)
        ai_prompt_news = (f"Generate a good news headline based on the following news title. Do not wrap it "
                          f"in quotes: {first_title}")
        ai_news_tweet = generate_ai_content(ai_prompt_news)
        tweet_content = f" Top News for {date_string}: {ai_news_tweet if ai_news_tweet else first_title}"
    else:
        tweet_content = request.form.get('tweet_content')

    job_id = f'{user_id}_{uuid.uuid4()}'

    if scheduled_time:
        scheduled_time_dt = datetime.strptime(scheduled_time, "%Y-%m-%dT%H:%M")
        delay = (scheduled_time_dt - datetime.now()).total_seconds()
        if delay > 0:
            if ai_prompt:
                twitter_scheduler.add_job(exec_post_tweet, 'date', run_date=scheduled_time_dt,
                                          args=[access_token, ai_prompt, None, True], id=job_id)
            else:
                twitter_scheduler.add_job(exec_post_tweet, 'date', run_date=scheduled_time_dt,
                                          args=[access_token, None, tweet_content, False], id=job_id)
            flash('Tweet scheduled successfully!', 'success')
        else:
            flash('Scheduled time has passed. Please choose a future time.', 'error')
    elif post_interval_hours:
        if ai_prompt:
            twitter_scheduler.add_job(exec_post_tweet, 'interval', seconds=post_interval_seconds,
                                      args=[access_token, ai_prompt, None, True], id=job_id,
                                      next_run_time=datetime.now())
        else:
            twitter_scheduler.add_job(exec_post_tweet, 'interval', seconds=post_interval_seconds,
                                      args=[access_token, None, tweet_content, False], id=job_id,
                                      next_run_time=datetime.now())
        flash(f'Tweet scheduled to be posted every {post_interval_hours} hours!', 'success')
    else:
        exec_post_tweet(access_token, None, tweet_content, is_ai_generated=False)
        flash('Tweet posted successfully!', 'success')

    new_scheduled_tweet = ScheduledTweet(
        user_id=user_id,
        tweet_content=tweet_content,
        scheduled_time=scheduled_time_dt if scheduled_time else None,
        post_interval_seconds=post_interval_seconds if post_interval_hours else None,
        job_id=job_id
    )
    db.session.add(new_scheduled_tweet)
    db.session.commit()
    return redirect(url_for('tweet_form'))


@app.route('/user_recurring_posts')
def user_recurring_posts():
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in to view recurring posts.', 'info')
        return redirect(url_for('login'))

    current_time = datetime.now()

    user_scheduled_ig_posts = ScheduledIGPost.query.filter(
        ScheduledIGPost.user_id == user_id,
        (
                (ScheduledIGPost.post_interval_seconds.isnot(None)) |
                ((ScheduledIGPost.scheduled_time.isnot(None)) & (ScheduledIGPost.scheduled_time > current_time))
        )
    ).all()

    user_scheduled_tweets = ScheduledTweet.query.filter(
        ScheduledTweet.user_id == user_id,
        (
                (ScheduledTweet.post_interval_seconds.isnot(None)) |
                ((ScheduledTweet.scheduled_time.isnot(None)) & (ScheduledTweet.scheduled_time > current_time))
        )
    ).all()

    user_scheduled_emails = ScheduledEmail.query.filter(
        ScheduledEmail.user_id == user_id,
        (
                (ScheduledEmail.post_interval_seconds.isnot(None)) |
                ((ScheduledEmail.scheduled_time.isnot(None)) & (ScheduledEmail.scheduled_time > current_time))
        )
    ).all()

    return render_template('user_recurring_posts.html', scheduled_ig_posts=user_scheduled_ig_posts,
                           scheduled_tweets=user_scheduled_tweets, scheduled_emails=user_scheduled_emails,
                           logged_in=True)


@app.route('/delete_scheduled_post/<platform>/<job_id>', methods=['POST'])
def delete_scheduled_post(platform, job_id):
    csrf.protect()
    user_id = session.get('user_id')
    if not user_id:
        flash('You need to log in to delete scheduled posts.', 'error')
        return redirect(url_for('login'))

    if platform == 'ig':
        view_scheduler = instagram_scheduler
        model = ScheduledIGPost
    elif platform == 'twitter':
        view_scheduler = twitter_scheduler
        model = ScheduledTweet
    elif platform == 'email':
        view_scheduler = email_scheduler
        model = ScheduledEmail
    else:
        flash('Invalid platform specified.', 'error')
        return redirect(url_for('user_recurring_posts'))

    try:
        view_scheduler.remove_job(job_id)
    except JobLookupError as e:
        flash('Failed to delete scheduled post. It may have already been deleted or executed.', 'error')
        app.logger.error(f"Attempted to delete a non-existent job on {platform}: {e}")

    model.query.filter_by(user_id=user_id, job_id=job_id).delete()
    db.session.commit()

    flash(f'Scheduled post on {platform} deleted successfully!', 'success')
    return jsonify(success=True)


@app.route('/tweet_form')
def tweet_form():
    access_token = session.get('access_token')
    if not access_token:
        return redirect(url_for("twitter_login"))
    return render_template('tweet_form.html', logged_in='user_id' in session)


email_scheduler = BackgroundScheduler()
email_scheduler.start()


@limiter.limit("50/hour")
@app.route("/send_email", methods=["POST"])
def send_email():
    csrf.protect()
    logging.info("Starting to process the /send_email request")
    user_email = request.form["user_email"]
    user_password = request.form["user_password"]
    unsorted_recipients = request.form["email_recipients"]
    recipients = [recipient.strip() for recipient in unsorted_recipients.split(",")]
    email_content = request.form["email_content"]
    ai_prompt = request.form.get("ai_prompt")
    scheduled_time = request.form.get("schedule_time")
    post_interval_hours = float(request.form.get("post_interval_hours") or 0)
    post_interval_seconds = post_interval_hours * 3600
    user_id = session.get('user_id')

    if ai_prompt:
        try:
            response = ai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "user", "content": ai_prompt},
                ],
                presence_penalty=0.6,
                frequency_penalty=0.6,
                temperature=0.7
            )
            email_content = response.choices[0].message.content.strip()
        except BadRequestError as e:
            app.logger.error(f"OpenAI API error: {e}")
            flash("An error occurred with the AI generation service. Please try again later.", "error")
        except RateLimitError:
            flash("OpenAI rate limit reached. Please try again later.")
        except EnvironmentError:
            flash("Error generating AI Tweet. Please try again later.")

    job_id = f'email_{user_id}_{uuid.uuid4()}'

    if scheduled_time:
        scheduled_time_dt = datetime.strptime(scheduled_time, "%Y-%m-%dT%H:%M")
        delay = (scheduled_time_dt - datetime.now()).total_seconds()
        if delay > 0:
            email_scheduler.add_job(exec_send_email, 'date', run_date=scheduled_time_dt,
                                    args=[user_email, user_password, recipients, email_content], id=job_id)
            flash('Email scheduled successfully!', 'success')
        else:
            flash('Scheduled time has passed. Please choose a future time.', 'error')
    elif post_interval_hours > 0:
        email_scheduler.add_job(exec_send_email, 'interval', seconds=post_interval_seconds,
                                args=[user_email, user_password, recipients, email_content], id=job_id,
                                next_run_time=datetime.now())
        flash(f'Email scheduled to be sent every {post_interval_hours} hours!', 'success')
    else:
        exec_send_email(user_email, user_password, recipients, email_content)
        flash('Email sent successfully!', 'success')

    new_scheduled_email = ScheduledEmail(
        user_id=user_id,
        email_content=email_content,
        recipients=",".join(recipients),
        scheduled_time=scheduled_time_dt if scheduled_time else None,
        post_interval_seconds=post_interval_seconds if post_interval_hours else None,
        job_id=job_id
    )
    db.session.add(new_scheduled_email)
    db.session.commit()
    return redirect(url_for('email_form'))


def exec_send_email(user_email, user_password, recipients, email_content):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(user_email, user_password)
    for recipient in recipients:
        server.sendmail(user_email, recipient, email_content)
    server.quit()


@app.route("/email_form")
def email_form():
    return render_template("emails.html", logged_in='user_id' in session)


# CLI command so that all the users can quickly be deleted, type in: flask delete-all-users
@app.cli.command("delete-all-users")
def delete_users():
    try:
        num_deleted = User.query.delete()
        db.session.commit()
        print(f"Deleted {num_deleted} users.")
    except Exception as e:
        db.session.rollback()
        print(f"An error occurred: {e}")


# CLI command so that ONE specific user can be deleted, type in: flask delete-users user1,user2,user3 (NO SPACES)
@app.cli.command("delete-users")
@click.argument("usernames")
def delete_users(usernames):
    username_list = usernames.split(',')
    deleted_users = 0
    for username in username_list:
        try:
            user = User.query.filter_by(username=username.strip()).first()
            if user:
                db.session.delete(user)
                db.session.commit()
                deleted_users += 1
                print(f"User '{username}' has been deleted.")
            else:
                print(f"User '{username}' not found.")
        except Exception as e:
            db.session.rollback()
            print(f"An error occurred while deleting '{username}': {e}")

    print(f"Total users deleted: {deleted_users}")


# CLI command so that a list of all users is displayed, type in: flask list-users
@click.command('list-users')
@with_appcontext
def list_users():
    users = User.query.all()
    print("List of users:")
    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Email: {user.email}")


def register_commands(app):
    app.cli.add_command(list_users)


register_commands(app)

# if __name__ == '__main__':
# app.run(debug=True)
