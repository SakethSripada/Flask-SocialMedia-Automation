# AI Social Media Automation

## Features

- **Automatic and regularly scheduled AI-generated social media posts**:
  - Upload images/enter text and schedule posts for Instagram or Twitter.
  - Use OpenAI API to generate images with DALL-E or tweets with GPT-3.5 Turbo.
  - Schedule recurring posts or tweets with AI-generated content.
  - Connect to Instagram and quickly post AI generated images based on your prompt.
  - Send emails from your Gmail account with automated scheduling.
  - Scheduled AI Generated news posting option using NewsAPI for daily top headlines.

## Upcoming Features
- Improved text overlay on images posted to Instagram.
- Access to external live data for post creation.

## Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SakethSripada/Flask-SocialMedia-Automation.git
   ```
   
2. **Obtain API Keys and Credentials**:
   - https://developer.twitter.com/en/portal/dashboard
   - https://support.google.com/accounts/answer/185833?hl=en
   - https://platform.openai.com/
   - https://newsapi.org/
3. **Create a 'secret.py' file and add values for the below variables**:
   ```python
    SECRET_KEY = 'your_secret_key' # Flask secret
    MAIL_SERVER = "smtp.gmail.com" 
    MAIL_PORT = 587
    MAIL_USERNAME = "your_email_address"
    MAIL_PASSWORD = "your_app_password" # Go to google account and set up App password
    MAIL_DEFAULT_SENDER = ("NoReply SM Automation", "your_email_address")
    API_KEY = "your_openai_api_key"
    TWITTER_CONSUMER_KEY = "your_twitter_consumer_key"
    TWITTER_CONSUMER_SECRET = "your_twitter_consumer_secret"
    BEARER_KEY = "your_twitter_bearer_key"
    ACCESS_TOKEN = "your_twitter_access_token"
    ACCESS_TOKEN_SECRET = "your_twitter_access_token_secret"
    OAUTH_CLIENT_ID = "your_oauth_client_id"
    OAUTH_CLIENT_SECRET = "your_oauth_client_secret"
    NEWS_API_KEY = "your_news_api_key"
    ```
4. **Install the required packages**:
    ```bash
    pip install -r requirements.txt
    ```
5. **Set up the Database**:
    ```bash
   flask db init
   flask db migrate -m "Initial migration."
    flask db upgrade
    ```
6. **Run application**:
    ```bash
    flask run
    ```

## Additional Notes and Commands:
- **Whenever you make changes to the database, run**:
    ```bash
    flask db migrate -m "migration message"
    ```
- **And then to update the database with the changes, run**:
    ```bash
    flask db upgrade
    ```
- **To Delete All Users, run**:
    ```bash
    flask delete-all-users
    ```
- **To Delete Specific Users, run**:
    ```bash
  flask delete-users user1,user2,user3
    ```
- **To List All Users, run**:
    ```bash
    flask list-users
    ```
