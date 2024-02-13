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
from itsdangerous import URLSafeTimedSerializer, BadSignature
from flask_migrate import Migrate
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect
from openai import OpenAI, BadRequestError, RateLimitError
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

# configurations
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
    return render_template("index.html", logged_in=logged_in)


# route for sending of verification email
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


# route for account registration
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


# function for posting
def exec_post(username, password, file_path, caption):  # necessary parameters for a post
    try:  # logging in to user account and performing action
        client = ig_login(username, password)
        client.photo_upload(file_path, caption)
    except EnvironmentError:
        print("Error. Image did not post")
        logging.error("Image post failed.")


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


# route for posting an image
@app.route("/post", methods=["POST"])
def post_image():
    csrf.protect()  # enabling csrf protection explicitly b/c this is not a flask-wtf form
    username = request.form['username']
    password = request.form['password']
    caption = request.form['caption']
    ai_prompt = request.form["ai_prompt"]
    scheduled_time = request.form.get("schedule_time")
    # check if the user entered a prompt for the AI, and if so, generate the image accordingly and then download it
    if ai_prompt:
        try:
            response = ai_client.images.generate(
                model="dall-e-2",
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
        except RateLimitError:
            flash("OpenAI rate limit reached. Please try again later.")
        except EnvironmentError:
            flash("Error generating AI Image. Please try again later.")
    else:
        photo = request.files["photo"]  # if no AI prompt entered, then use the user uploaded photo as the image
        unique_filename = secure_filename(f"{uuid.uuid4()}_{photo.filename}")
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)
        photo.save(file_path)

    if scheduled_time:
        scheduled_time = datetime.strptime(scheduled_time, "%Y-%m-%dT%H:%M")
        post_delay = (scheduled_time - datetime.now()).total_seconds()  # convert delay into seconds
        if post_delay > 0:  # check if the user wants to schedule in the future
            sched_item(post_delay, exec_post, username, password, file_path, caption)
            timestamps = session.get("scheduled_posts_timestamps", [])
            timestamps.append(datetime.utcnow())  # timestamps of when posts are made recorded for rate limiting
            session["scheduled_posts_timestamps"] = timestamps
            return "Successfully Scheduled."
        else:
            exec_post(username, password, file_path, caption)
            return "Scheduled time has passed. Image Posting Now."
    else:
        exec_post(username, password, file_path, caption)
        return "Successfully Posted"


# route for liking posts, similar logic to posting route
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


# function to rate limit (max 50 scheduled posts per hour), based on the number of timestamps logged
def rate_limit():
    timestamps = session.get("scheduled_posts_timestamps", [])
    prev_hour = datetime.utcnow() - timedelta(hours=1)
    timestamps_prev_hour = [ts.replace(tzinfo=None) for ts in timestamps if ts.replace(tzinfo=None) > prev_hour]
    session["scheduled_posts_timestamps"] = timestamps_prev_hour
    return len(timestamps_prev_hour) >= 50


# if interactions with instagram exceeds 50 in an hour, do not allow the action to be completed
@app.before_request
def check_rate_limit():
    if request.endpoint in ["post_image", "like_post", "comment_ig"]:
        if rate_limit():
            abort(429, description="You have reached 50 scheduled posts in one hour. No more posts may be scheduled.")


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

# if __name__ == '__main__':
# app.run(debug=True)
