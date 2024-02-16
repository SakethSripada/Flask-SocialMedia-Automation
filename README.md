# Flask Social Media Automation Application
Built on Flask using SQLAlchemy for DB

Functionality: 
As of the last README update, 2/15/24, the user can upload images/enter text, log in with their Instagram or Twitter credentials, and then either post immediately or schedule times at which they would like these images or tweets to be posted. Then at these times, the application will automatically upload these photos to their Instagram/Twitter page. The app also connects to the OpenAI API, so that the user may type in a prompt, and then DALL-E creates an image off of the user-entered prompt, and it is uploaded to the user's Instagram page (does not work yet with Twitter). The same functionality also exists with liking and commenting on posts(does not yet work with Twitter). There is also email verification and forgot password and CSRF protection is used. 

